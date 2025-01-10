package implementations

import "user_service/internal/services"

type AuthService struct {
}

func NewAuthService() services.IAuthUser {
	return &AuthService{}
}

// ForgotPassword implements services.IAuthUser.
func (a *AuthService) ForgotPassword() {
	panic("unimplemented")
}

// Login implements services.IAuthUser.
func (a *AuthService) Login() {
	panic("unimplemented")
}

// Register implements services.IAuthUser.
func (a *AuthService) Register() {
	panic("unimplemented")
}

// UpdatePassword implements services.IAuthUser.
func (a *AuthService) UpdatePassword() {
	panic("unimplemented")
}

// VerifyOTP implements services.IAuthUser.
func (a *AuthService) VerifyOTP() {
	panic("unimplemented")
}
