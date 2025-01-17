package implementations

import (
	"user_service/db/sqlc"
	"user_service/internal/services"
)

type AuthService struct {
	Queries *sqlc.Queries
}

func NewAuthService(queries *sqlc.Queries) services.IAuthUser {
	return &AuthService{
		Queries: queries,
	}
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
	// 1. Hash email
	// hashEmail := cryptor.GetHash()
}

// UpdatePassword implements services.IAuthUser.
func (a *AuthService) UpdatePassword() {
	panic("unimplemented")
}

// VerifyOTP implements services.IAuthUser.
func (a *AuthService) VerifyOTP() {
	panic("unimplemented")
}
