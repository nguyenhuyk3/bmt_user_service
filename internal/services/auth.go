package services

import (
	"context"
	"user_service/dto/request"
	"user_service/dto/response"
)

//go:generate mockgen -source=auth.go -destination=../mocks/auth.mock.go -package=mocks

type IRegistration interface {
	SendRegistrationOtp(ctx context.Context, arg request.SendOtpReq) (int, error)
	VerifyRegistrationOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error)
	CompleteRegistration(ctx context.Context, arg request.CompleteRegistrationReq) (int, error)
}

type ILogin interface {
	Login(ctx context.Context, arg request.LoginReq) (response.LoginRes, int, error)
}

type IForgotPassword interface {
	SendForgotPasswordOtp(ctx context.Context, arg request.SendOtpReq) (int, error)
	VerifyForgotPasswordOtp(ctx context.Context, arg request.VerifyOtpReq) (int, error)
	CompleteForgotPassword(ctx context.Context, arg request.CompleteForgotPasswordReq) (int, error)
}

type ILogout interface {
	Logout(ctx context.Context, email string) (int, error)
}

type IOAuth2Login interface {
	CheckOAuth2UserByEmail(ctx context.Context, email string) (bool, error)
	InserOAuth2UsertUser(ctx context.Context, arg response.OAuth2UserInfo) (int, error)
	ReturnToken(ctx context.Context, email string) (response.LoginRes, int, error)
}

type IAuth interface {
	ILogin
	IOAuth2Login
	IForgotPassword
	ILogout
}
