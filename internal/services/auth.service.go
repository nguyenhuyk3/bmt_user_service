package services

import (
	"context"
	"user_service/dto/request"
	"user_service/dto/response"
)

type IRegistration interface {
	SendRegistrationOtp(ctx context.Context, arg request.SendOtpReq) (int, error)
	VerifyOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error)
	CompleteRegistration(ctx context.Context, arg request.CompleteRegistrationReq) (int, error)
}

type ILogin interface {
	Login(ctx context.Context, arg request.LoginReq) (response.LoginRes, int, error)
}

type IForgotPassword interface {
	SendForgotPasswordOtp(ctx context.Context, arg request.SendOtpReq) (int, error)
	UpdatePassword(ctx context.Context, arg request.SendOtpReq) (int, error)
}

type IAuth interface {
	IRegistration
	ILogin
	IForgotPassword
}
