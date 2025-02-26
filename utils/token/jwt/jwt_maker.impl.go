package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	min_secret_key_size = 32
	access_duration     = 10 * time.Minute
	refresh_duration    = 60 * time.Minute
)

// JWTMaker is a JSON Web Token maker
type JWTMaker struct {
	secretKey string
}

// NewJWTMaker creates a new JWTMaker
func NewJWTMaker(secretKey string) (IMaker, error) {
	if len(secretKey) < min_secret_key_size {
		return nil, fmt.Errorf("invalid key size: must be at least %d characters", min_secret_key_size)
	}
	return &JWTMaker{secretKey}, nil
}

// CreateAccessToken implements Maker.
func (j *JWTMaker) CreateAccessToken(email string, role string) (string, *payload, error) {
	payload, err := NewPayload(email, role, access_duration)
	if err != nil {
		return "", payload, err
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	// Sign token with private key
	token, err := jwtToken.SignedString([]byte(j.secretKey))

	return token, payload, err
}

// VerifyAccessToken implements Maker.
func (j *JWTMaker) VerifyAccessToken(accessToken string) (*payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenErr
		}
		return []byte(j.secretKey), nil
	}

	parsedToken, err := jwt.ParseWithClaims(accessToken, &payload{}, keyFunc)
	if err != nil {
		vErr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(vErr.Inner, ExpiredTokenErr) {
			return nil, ExpiredTokenErr
		}
		return nil, InvalidTokenErr
	}

	payload, ok := parsedToken.Claims.(*payload)
	if !ok || !parsedToken.Valid {
		return nil, InvalidTokenErr
	}

	return payload, nil
}

// CreateRefreshToken implements Maker.
func (j *JWTMaker) CreateRefreshToken(email, role string) (string, *payload, error) {
	payload, err := NewPayload(email, role, refresh_duration)
	if err != nil {
		return "", nil, err
	}

	// Create a new JWT token with the claims
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	token, err := refreshToken.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", nil, err
	}

	return token, payload, nil
}

// VerifyRefreshToken implements Maker.
func (j *JWTMaker) VerifyRefreshToken(refreshToken string) (*payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenErr
		}
		return []byte(j.secretKey), nil
	}
	// Parse the token
	parsedToken, err := jwt.ParseWithClaims(refreshToken, &payload{}, keyFunc)
	if err != nil {
		vErr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(vErr.Inner, ExpiredTokenErr) {
			return nil, ExpiredTokenErr
		}
		return nil, InvalidTokenErr
	}
	// Extract claims from the token
	claims, ok := parsedToken.Claims.(*payload)
	if !ok || !parsedToken.Valid {
		return nil, InvalidTokenErr
	}
	return claims, nil
}

// RefreshAccessToken cấp lại access_token từ refresh_token
func (j *JWTMaker) RefreshAccessToken(refreshToken string) (string, *payload, error) {
	claims, err := j.VerifyRefreshToken(refreshToken)
	if err != nil {
		return "", nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	newAccessToken, newPayload, err := j.CreateAccessToken(claims.Email, claims.Role)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create new access token: %w", err)
	}
	return newAccessToken, newPayload, nil
}
