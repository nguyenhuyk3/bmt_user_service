package jwt

import "time"

// Maker is an interface for managing tokens
type Maker interface {
	// CreateToken creates a new token for a specific email and duration
	CreateAccessToken(email string, role string, duration time.Duration) (string, *payload, error)
	// VerifyToken checks if the token is valid or not
	VerifyAccessToken(token string) (*payload, error)
	// CreateRefreshToken creates a new refresh token
	CreateRefreshToken(email string, duration time.Duration) (string, error)
	// It verifies the validity of the provided refresh token and extracts the email if valid.
	VerifyRefreshToken(refreshToken string, secretKey string) (string, error)
}
