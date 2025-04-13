package jwt

//go:generate mockgen -source=maker.interface.go -destination=../../../internal/mocks/jwt_maker.mock.go -package=mocks

// Maker is an interface for managing tokens
type IMaker interface {
	CreateAccessToken(email string, role string) (string, *Payload, error)
	// VerifyToken checks if the token is valid or not
	VerifyAccessToken(token string) (*Payload, error)

	CreateRefreshToken(email, role string) (string, *Payload, error)
	// It verifies the validity of the provided refresh token and extracts the email if valid.
	VerifyRefreshToken(refreshToken string) (*Payload, error)
	RefreshAccessToken(refreshToken string) (string, *Payload, error)
}
