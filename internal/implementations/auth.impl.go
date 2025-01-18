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
func (a *authService) Register(ctx context.Context, req request.RegisterReq) (int, error) {
	// Check if email has otp in redis or not
	emailIsInRegistrationKey := fmt.Sprintf("email::%s", req.Email)
	isExists, err := redis.ExistsKey(emailIsInRegistrationKey)
	if isExists && err == nil {
		return http.StatusConflict, errors.New("email is in registration status")
	}
	// Check if email already exists or not
	isExists, err = a.Queries.CheckAccountExistsByEmail(ctx, req.Email)
	if isExists && err == nil {
		return http.StatusConflict, errors.New("email already exists")
	}

	expirationTime := 10
	// Save email is in registration status
	_ = redis.Save(emailIsInRegistrationKey, req.Email, int64(expirationTime))
	// Saving otp into redis with time to live is 10 minutes
	otp, _ := generator.GenerateNumberBasedOnLength(6)
	emailWithOtpKey := fmt.Sprintf("%s::otp", req.Email)
	_ = redis.Save(emailWithOtpKey, otp, int64(expirationTime))

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
		redis.Delete(emailWithOtpKey)

		return http.StatusInternalServerError, errors.New("failed to send mail, please try again later")
	}

	return http.StatusOK, nil
}

// UpdatePassword implements services.IAuthUser.
func (a *authService) UpdatePassword() {
	panic("unimplemented")
}

// VerifyOTP implements services.IAuthUser.
func (a *authService) VerifyOTP() {
	panic("unimplemented")
}
