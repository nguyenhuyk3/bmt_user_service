package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"user_service/global"
)

func AesEncrypt(email string) (string, error) {
	key := []byte(global.Config.Server.SercetKey)
	// Create block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Convert email to bytes
	plaintext := []byte(email)
	// Create buffer for encryption result
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	// Generate random IV
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to create IV: %v", err)
	}

	// Encryption
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// Convert to base64 for easy storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func AesDecrypt(encryptedEmail string) (string, error) {
	key := []byte(global.Config.Server.SercetKey)
	// Decode base64 string to bytes
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedEmail)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}
	// Create block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Check for valid length
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("encrypted email is too short")
	}

	// Extract IV from ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Decryption
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
