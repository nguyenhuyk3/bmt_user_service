package cryptor

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns the bcrypt hash of the password
func BcryptHashInput(input string) (string, error) {
	hashedInput, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash input: %w", err)
	}

	return string(hashedInput), nil
}

// CheckPassword checks if the provided password is correct or not
func BcryptCheckInput(input string, hashedInput string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedInput), []byte(input))
}
