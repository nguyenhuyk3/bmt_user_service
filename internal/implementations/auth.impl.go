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
	// 1. Check if email already exists or not
	isExists, err := a.Queries.CheckAccountExistsByEmail(ctx, req.Email)
	if isExists && err != nil {
		return http.StatusConflict, errors.New("email already exists")
	}

	otp, _ := generator.GenerateNumberBasedOnLength(6)
	// 2. Saving otp into redis with time live is 10 minutes
	fmt.Printf("otp is ::%s\n", otp)
	err = redis.AddOTP(req.Email, otp, 10)
	if err != nil {
		return http.StatusInternalServerError, errors.New("failed to generate OTP, please try again later")
	}

	// 3. Send mail
	err = mail.SendTemplateEmailOtp([]string{req.Email},
		"1notthingm@gmail.com", "otp_email.html",
		map[string]interface{}{
			"otp": otp,
		})
	if err != nil {
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
