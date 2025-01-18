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
	Queries *sqlc.Queries
}

func NewAuthService() services.IAuth {
	return &authService{
		Queries: global.Queries,
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
func (a *authService) SendOtp(ctx context.Context, req request.SendOtpReq) (int, error) {
	// Check if email has otp in redis or not
	emailIsInRegistrationKey := fmt.Sprintf("otp::%s", req.Email)
	isExists, err := redis.ExistsKey(emailIsInRegistrationKey)
	if isExists && err == nil {
		return http.StatusConflict, errors.New("email is in registration status")
	}
	// Check if email already exists or not
	isExists, err = a.Queries.CheckAccountExistsByEmail(ctx, req.Email)
	if isExists && err == nil {
		return http.StatusConflict, errors.New("email already exists")
	}

	expirationTime := int64(10)
	otp, _ := generator.GenerateNumberBasedOnLength(6)
	// Save email and otp is in registration status
	_ = redis.Save(emailIsInRegistrationKey, request.VerifyOtpReq{
		Email: req.Email,
		Otp:   otp,
	}, expirationTime)

	// Send mail
	fromEmail := "1notthingm@gmail.com"
	err = mail.SendTemplateEmailOtp([]string{req.Email},
		fromEmail, "otp_email.html",
		map[string]interface{}{
			"otp":             otp,
			"from_email":      fromEmail,
			"expiration_time": expirationTime,
		})
	if err != nil {
		redis.Delete(emailIsInRegistrationKey)

		return http.StatusInternalServerError, errors.New("failed to send mail, please try again later")
	}

	return http.StatusOK, nil
}

// VerifyOTP implements services.IAuthUser.
func (a *authService) VerifyOtp(ctx context.Context, req request.VerifyOtpReq) (int, error) {
	key := fmt.Sprintf("otp::%s", req.Email)
	var result request.VerifyOtpReq
	err := redis.Get(key, &result)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	if req.Email == result.Email || req.Otp == result.Otp {
		_ = redis.Delete(key)

		return http.StatusOK, nil
	}

	return http.StatusUnauthorized, fmt.Errorf("invalid email or OTP")
}

// UpdatePassword implements services.IAuthUser.
func (a *authService) UpdatePassword() {
	panic("unimplemented")
}
