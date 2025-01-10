package services

import "user_service/internal/services/auth"

type AuthService struct {
}

func NewAuthService() auth.IAuthUser {
	return &AuthService{}
}

// ForgotPassword implements auth.IAuthUser.
func (a *AuthService) ForgotPassword() {
	panic("unimplemented")
}

// Login implements auth.IAuthUser.
func (a *AuthService) Login() {
	panic("unimplemented")
}

// Register implements auth.IAuthUser.
func (a *AuthService) Register() {
	panic("unimplemented")
}

// UpdatePassword implements auth.IAuthUser.
func (a *AuthService) UpdatePassword() {
	panic("unimplemented")
}

// VerifyOTP implements auth.IAuthUser.
func (a *AuthService) VerifyOTP() {
	panic("unimplemented")
}
