package redis

import (
	"context"
	"fmt"
	"time"
	"user_service/global"
)

var (
	ctx = context.Background()
)

// expirationTime must be in "minute" format
func AddOTP(email string, otp string, expirationTime int64) error {
	key := fmt.Sprintf("%s::%s", email, otp)
	err := global.RDb.SetEx(ctx, key, otp, time.Duration(expirationTime)*time.Minute).Err()
	if err != nil {
		return fmt.Errorf("failed to save OTP: %w", err)
	}
	return nil
}
