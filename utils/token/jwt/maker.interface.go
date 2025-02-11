package jwt

// Maker is an interface for managing tokens
type IMaker interface {
	CreateAccessToken(email string, role string) (string, *payload, error)
	// VerifyToken checks if the token is valid or not
	VerifyAccessToken(token string) (*payload, error)

	CreateRefreshToken(email, role string) (string, *payload, error)
	// It verifies the validity of the provided refresh token and extracts the email if valid.
	VerifyRefreshToken(refreshToken string) (*payload, error)
	RefreshAccessToken(refreshToken string) (string, *payload, error)
}
