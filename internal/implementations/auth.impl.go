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
	key := fmt.Sprintf("%s%s", global.OTP_KEY, arg.Email)
	isExists := redis.ExistsKey(key)
	if !isExists {
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
		Email: arg.Email,
		Otp:   otp,
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
	key := fmt.Sprintf("otp::%s", arg.Email)
	var result request.VerifyOtpReq
	err := redis.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if arg.Email == result.Email || arg.Otp == result.Otp {
		_ = redis.Delete(key)
		_ = redis.Save(fmt.Sprintf("%s%s", global.COMPLETE_REGISTRATION_PROCESS, arg.Email),
			map[string]interface{}{
				"email": arg.Email,
			}, 10)

		return http.StatusOK, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid email or OTP")
}

// CompleteRegister implements services.IAuth.
func (a *authService) CompleteRegister(ctx context.Context, arg request.CompleteRegisterReq) (int, error) {
	key := fmt.Sprintf("%s%s", global.COMPLETE_REGISTRATION_PROCESS, arg.Account.Email)
	isExists := redis.ExistsKey(key)
	if !isExists {
		return http.StatusNotFound, errors.New("email is not found in redis")
	}

	return http.StatusOK, nil
}

// UpdatePassword implements services.IAuthUser.
func (a *authService) UpdatePassword() {
	panic("unimplemented")
}
