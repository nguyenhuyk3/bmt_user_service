package forgotpassword

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

type fotgotPasswordService struct {
	SqlStore    sqlc.IStore
	RedisClient services.IRedis
	Writer      services.IMessageBrokerWriter
}

const (
	ten_minutes   = 10
	three_minutes = 3
	three_hours   = 3 * 60
)

type blockSendForgotPasswordOtp struct {
	Count int `json:"count" binding:"required"`
}

type verifyOtp struct {
	EncryptedEmail string `json:"encrypted_email" binding:"required"`
	Otp            string `json:"otp" binding:"required"`
}

/*
* SendForgotPasswordOtp will include 6 steps:
*	- Step 1: Check if the email exists before
*	- Step 2: Check if this email is locked (check blockKey) or not (avoid spam)
*	- Step 3: Check how many times this email has been sent, if more than 2 times, a key (blockKey) will be created in redis (within 3 hours)
*	- Step 4: Check if the email has an expired otp code or not (check forgotPasswordKey), because each email will exist for 3 minutes and after 3 minutes it can only be sent once more
*	- Step 5: If it passes the above conditions, the email will be sent
*	- Step 6: If the email is sent successfully, we will increase the attempKey by 1
 */
// SendForgotPasswordOtp implements services.IForgotPassword.
func (f *fotgotPasswordService) SendForgotPasswordOtp(ctx context.Context, arg request.SendOtpReq) (int, error) {
	// * Step 1
	isExists, err := f.SqlStore.CheckAccountExistsByEmailAndSource(ctx,
		sqlc.CheckAccountExistsByEmailAndSourceParams{
			Email: arg.Email,
			Source: sqlc.NullSources{
				Sources: sqlc.SourcesApp,
				Valid:   true,
			}})
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to check email existence in database")
	}

	if !isExists {
		return http.StatusNotFound, errors.New("email doesn't exist")
	}

	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	// * Step 2
	// This key will keep track of how many times the email has been sent.
	attemptKey := fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail)
	// Check if this key has been blocked due to exceeding 3 email attempts
	blockKey := fmt.Sprintf("%s%s", global.BLOCK_FORGOT_PASSWORD_KEY, aesEncryptedEmail)
	blockedTTL, err := f.RedisClient.GetTTL(blockKey)
	if err == nil && blockedTTL > 0 {
		_ = f.RedisClient.Delete(attemptKey)

		return http.StatusTooManyRequests, fmt.Errorf("you cannot make a request in: %v", blockedTTL)
	}
	// * Step 3
	var res blockSendForgotPasswordOtp

	err = f.RedisClient.Get(attemptKey, &res)
	if err != nil {
		// This code will be perform at first
		res.Count = 0
		_ = f.RedisClient.Save(attemptKey, res, three_hours)
	}

	if res.Count > 2 {
		_ = f.RedisClient.Save(blockKey, map[string]interface{}{
			"blocked": true,
		}, three_hours)
		_ = f.RedisClient.Delete(attemptKey)

		return http.StatusTooManyRequests, errors.New("you can't do the request in 3 hours")
	}
	// * Step 4
	// This key will hold the value of the otp code
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)
	// Check remaining time of this key
	remainingTime, _ := f.RedisClient.GetTTL(forgotPasswordKey)
	if remainingTime > 0 {
		return http.StatusTooManyRequests, fmt.Errorf("please try again later %v", remainingTime)
	}
	// * Step 5
	otp, _ := generator.GenerateStringNumberBasedOnLength(6)
	message := messages.MailMessage{
		Payload: messages.OtpMessage{
			Email:          arg.Email,
			Otp:            otp,
			ExpirationTime: three_minutes,
		},
	}
	// * Step 6
	err = f.Writer.SendMessage(
		ctx,
		global.FORGOT_PASSWORD_OTP_EMAIL_TOPIC,
		arg.Email,
		message)
	if err == nil {
		bcryptEncryptedEmail, _ := cryptor.BcryptHashInput(arg.Email)
		_ = f.RedisClient.Save(forgotPasswordKey, map[string]interface{}{
			"encrypted_email": bcryptEncryptedEmail,
			"otp":             otp,
		}, three_minutes)

		res.Count++
		_ = f.RedisClient.Save(attemptKey, res, three_hours)

		return http.StatusOK, nil
	} else {
		_ = f.RedisClient.Delete(attemptKey)

		return http.StatusInternalServerError, fmt.Errorf("send mail failed: %v", err)
	}
}

// VerifyForgotPasswordOtp implements services.IForgotPassword.
func (f *fotgotPasswordService) VerifyForgotPasswordOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error) {
	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	forgotPasswordKey := fmt.Sprintf("%s%s", global.FORGOT_PASSWORD_KEY, aesEncryptedEmail)

	var result verifyOtp
	err := f.RedisClient.Get(forgotPasswordKey, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch == nil && arg.Otp == result.Otp {
		_ = f.RedisClient.Delete(forgotPasswordKey)
		_ = f.RedisClient.Save(fmt.Sprintf("%s%s", global.COMPLETE_FORGOT_PASSWORD_PROCESS, aesEncryptedEmail),
			map[string]interface{}{
				"encrypted_email": result.EncryptedEmail,
			}, ten_minutes)

		return http.StatusOK, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid otp")
}

// CompleteForgotPassword implements services.IForgotPassword.
func (f *fotgotPasswordService) CompleteForgotPassword(ctx context.Context, arg request.CompleteForgotPasswordReq) (int, error) {
	aesEncryptedEmail, _ := cryptor.AesEncrypt(arg.Email)
	key := fmt.Sprintf("%s%s", global.COMPLETE_FORGOT_PASSWORD_PROCESS, aesEncryptedEmail)
	isExists := f.RedisClient.ExistsKey(key)
	if !isExists {
		return http.StatusConflict, errors.New("invalid request for complete forgot password")
	}

	var result verifyOtp
	err := f.RedisClient.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	isMatch := cryptor.BcryptCheckInput(result.EncryptedEmail, arg.Email)
	if isMatch != nil {
		return http.StatusUnauthorized, errors.New("email mismatch or invalid request")
	}

	newPassword, _ := cryptor.BcryptHashInput(arg.NewPassword)
	err = f.SqlStore.UpdatePassword(ctx, sqlc.UpdatePasswordParams{
		Email:    arg.Email,
		Password: newPassword,
	})
	if err != nil {
		return http.StatusInternalServerError, err
	}

	_ = f.RedisClient.Delete(fmt.Sprintf("%s%s", global.ATTEMPT_KEY, aesEncryptedEmail))
	_ = f.RedisClient.Delete(key)

	return http.StatusOK, nil
}

func NewForgotPasswordSevice(
	sqlStore sqlc.IStore,
	redisClient services.IRedis,
	writer services.IMessageBrokerWriter,
) services.IForgotPassword {
	return &fotgotPasswordService{
		SqlStore:    sqlStore,
		RedisClient: redisClient,
		Writer:      writer,
	}
}
