package auth

type IAuthUser interface {
	Register()
	Login()
	ForgotPassword()
	UpdatePassword()
	VerifyOTP()
}
