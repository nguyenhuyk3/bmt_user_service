package services

import (
	"context"
	"user_service/dto/request"
)

type IAuth interface {
	SendOtp(ctx context.Context, req request.SendOtpReq) (int, error)
	VerifyOtp(ctx context.Context, req request.VerifyOtpReq) (int, error)
	CompleteRegister(ctx context.Context, req request.CompleteRegisterReq) (int, error)
	Login()
	ForgotPassword()
	UpdatePassword()
}
