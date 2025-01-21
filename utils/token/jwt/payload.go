package jwt

import (
	"errors"
	"time"

	"github.com/gofrs/uuid"
)

// Different types of error returned by the VerifyToken function
var (
	InvalidTokenErr = errors.New("token is invalid")
	ExpiredTokenErr = errors.New("token has expired")
)

// Payload contains the payload data of the token
type payload struct {
	Id        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

// NewPayload creates a new token payload with a specific username and duration
func NewPayload(email string, role string, duration time.Duration) (*payload, error) {
	tokenId, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	payload := &payload{
		Id:        tokenId,
		Email:     email,
		Role:      role,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}

	return payload, nil
}

// Valid checks if the token payload is valid or not
// This method will implement Claims interface from "jwt" package
func (p *payload) Valid() error {
	if time.Now().After(p.ExpiredAt) {
		return ExpiredTokenErr
	}

	return nil
}
