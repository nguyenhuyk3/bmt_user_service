package jwt

import (
	"errors"
	"time"
	"user_service/global"

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
	Issuer    string    `json:"iss"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
	Issued    int64     `json:"issued"`
	Exp       int64     `json:"exp"`
}

// NewPayload creates a new token payload with a specific username and duration
func NewPayload(email string, role string, duration time.Duration) (*payload, error) {
	tokenId, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	payload := &payload{
		Id:        tokenId,
		Issuer:    global.Config.Server.Issuer,
		Email:     email,
		Role:      role,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
		Issued:    time.Now().Unix(),
		Exp:       time.Now().Add(duration).Unix(),
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
