package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const minSecretKeySize = 32

// JWTMaker is a JSON Web Token maker
type JWTMaker struct {
	secretKey string
}

// NewJWTMaker creates a new JWTMaker
func NewJWTMaker(secretKey string) (Maker, error) {
	if len(secretKey) < minSecretKeySize {
		return nil, fmt.Errorf("invalid key size: must be at least %d characters", minSecretKeySize)
	}

	return &JWTMaker{secretKey}, nil
}

// CreateAccessToken implements Maker.
func (j *JWTMaker) CreateAccessToken(email string, role string, duration time.Duration) (string, *payload, error) {
	payload, err := NewPayload(email, role, duration)
	if err != nil {
		return "", payload, err
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	// Sign token with private key
	token, err := jwtToken.SignedString([]byte(j.secretKey))

	return token, payload, err
}

// VerifyAccessToken implements Maker.
func (j *JWTMaker) VerifyAccessToken(token string) (*payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenErr
		}

		return []byte(j.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &payload{}, keyFunc)
	if err != nil {
		vErr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(vErr.Inner, ExpiredTokenErr) {
			return nil, ExpiredTokenErr
		}
		return nil, InvalidTokenErr
	}

	payload, ok := jwtToken.Claims.(*payload)
	if !ok {
		return nil, InvalidTokenErr
	}

	return payload, nil
}

// CreateRefreshToken implements Maker.
func (j *JWTMaker) CreateRefreshToken(email string, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"email":     email,
		"exp":       time.Now().Add(duration).Unix(), // Expiration time
		"issued_at": time.Now().Unix(),               // Issued at
	}

	// Create a new JWT token with the claims
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := refreshToken.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", err
	}

	return token, nil
}

// VerifyRefreshToken implements Maker.
func (j *JWTMaker) VerifyRefreshToken(refreshToken string, secretKey string) (string, error) {
	// Define a key function for validating the token's signing method
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, InvalidTokenErr
		}

		return []byte(j.secretKey), nil
	}

	// Parse the token
	parsedToken, err := jwt.Parse(refreshToken, keyFunc)
	if err != nil {
		vErr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(vErr.Inner, ExpiredTokenErr) {
			return "", ExpiredTokenErr
		}
		return "", InvalidTokenErr
	}

	// Extract claims from the token
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return "", InvalidTokenErr
	}

	// Extract the user ID from the claims
	email, ok := claims["email"].(string)
	if !ok {
		return "", InvalidTokenErr
	}

	return email, nil
}
