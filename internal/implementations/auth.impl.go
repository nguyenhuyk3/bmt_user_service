package implementations

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"user_service/db/sqlc"
	"user_service/dto/request"
	"user_service/global"
	"user_service/internal/services"
	"user_service/utils/cryptor"
	"user_service/utils/generator"
	"user_service/utils/redis"
	mail "user_service/utils/sender"
)

type authService struct {
	SqlStore *sqlc.SqlStore
}

func NewAuthService(sqlStore *sqlc.SqlStore) services.IAuth {
	return &authService{
		SqlStore: sqlStore,
	}
}

// ForgotPassword implements services.IAuthUser.
func (a *authService) ForgotPassword() {
	panic("unimplemented")
}

// Login implements services.IAuthUser.
func (a *authService) Login() {
	panic("unimplemented")
}

// Register implements services.IAuthUser.
func (a *authService) SendOtp(ctx context.Context, arg request.SendOtpReq) (int, error) {
	// Check if email has otp in redis or not
	encryptedEmail, _ := cryptor.BcryptHashInput(arg.Email)
	key := fmt.Sprintf("%s%s", global.OTP_KEY, encryptedEmail)
	isExists := redis.ExistsKey(key)
	if isExists {
		return http.StatusConflict, errors.New("email is in registration status")
	}
	// Check if email already exists or not
	isExists, err := a.SqlStore.Queries.CheckAccountExistsByEmail(ctx, arg.Email)
	if isExists && err == nil {
		return http.StatusConflict, errors.New("email already exists")
	}

	expirationTime := int64(10)
	otp, _ := generator.GenerateNumberBasedOnLength(6)
	// Save email and otp is in registration status
	_ = redis.Save(key, request.VerifyOtpReq{
		EncryptedEmail: encryptedEmail,
		Otp:            otp,
	}, expirationTime)

	// Send mail
	fromEmail := "1notthingm@gmail.com"
	err = mail.SendTemplateEmailOtp([]string{arg.Email},
		fromEmail, "otp_email.html",
		map[string]interface{}{
			"otp":             otp,
			"from_email":      fromEmail,
			"expiration_time": expirationTime,
		})
	if err != nil {
		redis.Delete(key)

		return http.StatusInternalServerError, errors.New("failed to send mail, please try again later")
	}

	return http.StatusOK, nil
}

// VerifyOTP implements services.IAuthUser.
func (a *authService) VerifyOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error) {
	key := fmt.Sprintf("%s%s", global.OTP_KEY, arg.EncryptedEmail)
	var result request.VerifyOtpReq

	err := redis.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	isMatch := cryptor.BcryptCheckInput(arg.Email, result.EncryptedEmail)

	if isMatch == nil && arg.Otp == result.Otp {
		_ = redis.Delete(key)
		_ = redis.Save(fmt.Sprintf("%s%s", global.COMPLETE_REGISTRATION_PROCESS, arg.EncryptedEmail),
			map[string]interface{}{
				"encrypted_email": arg.EncryptedEmail,
			}, 10)

		return http.StatusOK, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid email or otp")
}

// CompleteRegister implements services.IAuth.
func (a *authService) CompleteRegistration(ctx context.Context, arg request.CompleteRegistrationReq) (int, error) {
	key := fmt.Sprintf("%s%s", global.COMPLETE_REGISTRATION_PROCESS, arg.EncryptedEmail)
	fmt.Println(arg.EncryptedEmail)
	isExists := redis.ExistsKey(key)
	if !isExists {
		return http.StatusNotFound, errors.New("email is not found in redis")
	}

	isMatch := cryptor.BcryptCheckInput(arg.Account.Email, arg.EncryptedEmail)
	if isMatch != nil {
		return http.StatusBadRequest, errors.New("encrypted email and email don't match")
	}

	err := a.SqlStore.InsertAccountTran(ctx, arg)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("failed to complete registration: %w", err)
	}

	_ = redis.Delete(key)

	return http.StatusCreated, nil
}

// UpdatePassword implements services.IAuthUser.
func (a *authService) UpdatePassword() {
	panic("unimplemented")
}
