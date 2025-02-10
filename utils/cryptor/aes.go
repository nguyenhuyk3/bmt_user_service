package cryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"user_service/global"
)

// pkcs7Pad adds padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(data, padtext...)
}

// pkcs7Unpad removes padding
func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])

	return data[:(length - unpadding)]
}

var fixedIV = []byte(global.Config.Server.FixedIv)

func AesEncrypt(text string) (string, error) {
	keyBytes := []byte(global.Config.Server.SercetKey)
	block, err := aes.NewCipher(keyBytes[:32])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	plaintext := []byte(text)
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))

	stream := cipher.NewCBCEncrypter(block, fixedIV)
	stream.CryptBlocks(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypt text
func AesDecrypt(encryptedText string) (string, error) {
	keyBytes := []byte(global.Config.Server.SercetKey)
	block, err := aes.NewCipher(keyBytes[:32])
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding: %v", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext is too short, must be at least %d bytes", aes.BlockSize)
	}

	mode := cipher.NewCBCDecrypter(block, fixedIV)
	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext := pkcs7Unpad(ciphertext)

	return string(plaintext), nil
}
