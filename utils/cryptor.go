package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

func GetHash(key string) string {
	hash := sha256.New()
	hash.Write([]byte(key))
	hashBytes := hash.Sum(nil)

	return hex.EncodeToString(hashBytes)
}

// GeneratareSalt generate a random salt
func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	/*
		Result is generated randomly
		and will have a value in range [0-255]
	*/
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	return hex.EncodeToString(salt), nil
}

func HashPassword(password string, salt string) string {
	// Concatenate password and salt
	saltedPassword := password + salt
	// Hash the combined string
	hashPass := sha256.Sum256(([]byte(saltedPassword)))

	return hex.EncodeToString(hashPass[:])
}

func MatchingPassword(storedHash string, password string, salt string) bool {
	hashPassword := HashPassword(password, salt)

	return storedHash == hashPassword
}
