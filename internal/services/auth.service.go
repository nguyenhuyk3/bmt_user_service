package services

type IAuthUser interface {
	Register()
	Login()
	ForgotPassword()
	UpdatePassword()
	VerifyOTP()
}
