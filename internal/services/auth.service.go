package services

import (
	"context"
	"user_service/dto/request"
)

type IAuth interface {
	Register(ctx context.Context, req request.RegisterReq) (int, error)
	Login()
	ForgotPassword()
	UpdatePassword()
	VerifyOTP()
}
