package registration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"user_service/db/sqlc"
	"user_service/dto/messages"
	"user_service/dto/request"
	"user_service/global"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/generator"
)

type registrationService struct {
	SqlStore      sqlc.IStore
	RedisClient   services.IRedis
	MessageBroker services.IMessageBroker
}

const (
	ten_minutes = 10
)

type verifyOtp struct {
	EncryptedEmail string `json:"encrypted_email" binding:"required"`
	Otp            string `json:"otp" binding:"required"`
}

/*
* SendRegistrationOtp will consist of 3 steps:
*	- Step 1: Check in redis whether the registered email has an otp code or not
*				(If the otp code exists, the email is in the registration process)
*	- Step 2: If step 1 is passed, check whether the registered email is in the process of completion or not
*	- Step 3: If the above steps are passed, start sending the OTP code
 */
// SendRegistrationOtp implements services.IRegistration.
func (r *registrationService) SendRegistrationOtp(ctx context.Context, arg request.SendOtpReq) (int, error) {
	// * Step 1
	encryptedAesEmail, _ := cryptor.AesEncrypt(arg.Email)
	registrationOtpKey := fmt.Sprintf("%s%s", global.REDIS_REGISTRATION_OTP_KEY, encryptedAesEmail)
	isExists := r.RedisClient.ExistsKey(registrationOtpKey)
	if isExists {
		return http.StatusConflict, errors.New("email is in registration status")
	}
	// * Step 2
	completeRegistrationProcessKey := fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedAesEmail)
	isExists = r.RedisClient.ExistsKey(completeRegistrationProcessKey)
	if isExists {
		return http.StatusConflict, errors.New("email is in complete registration process")
	}

	isExists, err := r.SqlStore.CheckAccountExistsByEmailAndSource(ctx,
		sqlc.CheckAccountExistsByEmailAndSourceParams{Email: arg.Email, Source: sqlc.NullSources{
			Sources: sqlc.SourcesApp,
			Valid:   true,
		}})
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to check email existence in database")
	}
	if isExists {
		return http.StatusConflict, errors.New("email already exists")
	}
	// * Step 3
	otp, _ := generator.GenerateStringNumberBasedOnLength(6)
	encryptedBcryptEmail, _ := cryptor.BcryptHashInput(arg.Email)
	// Save email and otp is in registration status
	_ = r.RedisClient.Save(registrationOtpKey, verifyOtp{
		EncryptedEmail: encryptedBcryptEmail,
		Otp:            otp,
	}, ten_minutes)
	err = r.MessageBroker.SendMessage(
		ctx,
		global.REGISTRATION_OTP_EMAIL_TOPIC,
		arg.Email,
		messages.MailMessage{
			Payload: messages.OtpMessage{
				Email:          arg.Email,
				Otp:            otp,
				ExpirationTime: ten_minutes,
			},
		})
	if err != nil {
		r.RedisClient.Delete(registrationOtpKey)

		return http.StatusInternalServerError, fmt.Errorf("failed to send OTP to Kafka: %v", err)
	}

	return http.StatusOK, nil
}

// VerifyRegistrationOtp implements services.IRegistration.
func (r *registrationService) VerifyRegistrationOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error) {
	encryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	key := fmt.Sprintf("%s%s", global.REDIS_REGISTRATION_OTP_KEY, encryptedEmail)

	var result verifyOtp
	err := r.RedisClient.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("otp has expired: %v", err)
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch == nil && arg.Otp == result.Otp {
		_ = r.RedisClient.Delete(key)
		_ = r.RedisClient.Save(fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedEmail),
			map[string]interface{}{
				"encrypted_email": result.EncryptedEmail,
			}, ten_minutes)

		return http.StatusOK, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid email or otp")
}

// CompleteRegistration implements services.IRegistration.
func (r *registrationService) CompleteRegistration(ctx context.Context, arg request.CompleteRegistrationReq) (int, error) {
	encryptedEmail, _ := cryptor.AesEncrypt(arg.Account.Email)
	key := fmt.Sprintf("%s%s", global.REDIS_COMPLETE_REGISTRATION_PROCESS, encryptedEmail)

	var result verifyOtp

	err := r.RedisClient.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("email is not in complete registration process %v", err)
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Account.Email)
	if isMatch != nil {
		return http.StatusBadRequest, errors.New("encrypted email and email don't match")
	}

	err = r.SqlStore.InsertAccountTran(ctx, arg, false)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to complete registration: %w", err)
	}

	_ = r.RedisClient.Delete(key)

	return http.StatusCreated, nil
}

func NewRegistrationService(
	sqlStore sqlc.IStore,
	redisClient services.IRedis,
	messageBroker services.IMessageBroker) services.IRegistration {
	return &registrationService{
		SqlStore:      sqlStore,
		RedisClient:   redisClient,
		MessageBroker: messageBroker,
	}
}
