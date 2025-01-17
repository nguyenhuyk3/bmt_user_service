package generator

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const (
	digits = "0123456789"
)

func GenerateNumberBasedOnLength(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be greater than 0")
	}

	otp := make([]byte, length)

	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %v", err)
		}

		otp[i] = digits[num.Int64()]
	}

	return string(otp), nil
}
