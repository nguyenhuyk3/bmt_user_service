package services

import (
	"context"
	"user_service/dto/request"
)

type IAuth interface {
	SendOTP(ctx context.Context, req request.SendOTPReq) (int, error)
	Login()
	ForgotPassword()
	UpdatePassword()
	VerifyOTP()
}
