package cryptor

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptHashInput returns the bcrypt hash of the input
func BcryptHashInput(input string) (string, error) {
	hashedInput, err := bcrypt.GenerateFromPassword([]byte(input), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash input: %w", err)
	}

	return string(hashedInput), nil
}

// BcryptCheckInput checks if the provided input is correct or not
func BcryptCheckInput(hashedInput string, input string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedInput), []byte(input))
}
