package services

import (
	"context"
	"user_service/dto/request"
	"user_service/dto/response"
)

type IAuth interface {
	SendOtp(ctx context.Context, arg request.SendOtpReq) (int, error)
	VerifyOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error)
	CompleteRegistration(ctx context.Context, arg request.CompleteRegistrationReq) (int, error)
	Login(ctx context.Context, arg request.LoginReq) (response.LoginRes, int, error)
	ForgotPassword()
	UpdatePassword()
}
