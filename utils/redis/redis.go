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
func Save(key, value string, expirationTime int64) error {
	err := global.RDb.SetEx(ctx, key, value, time.Duration(expirationTime)*time.Minute).Err()
	if err != nil {
		return fmt.Errorf("failed to save OTP: %w", err)
	}

	return nil
}

func ExistsKey(key string) (bool, error) {
	count, err := global.RDb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}

	// `count > 0` means the key exists
	return count > 0, nil
}

func Delete(key string) error {
	err := global.RDb.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}
