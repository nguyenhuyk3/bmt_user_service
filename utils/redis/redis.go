package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"user_service/global"

	"github.com/go-redis/redis"
)

var (
	ctx = context.Background()
)

// expirationTime must be in "minute" format
func Save(key string, value interface{}, expirationTime int64) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to serialize value: %w", err)
	}

	err = global.RDb.SetEx(ctx, key, jsonValue, time.Duration(expirationTime)*time.Minute).Err()
	if err != nil {
		return fmt.Errorf("failed to save value: %w", err)
	}

	return nil
}

func ExistsKey(key string) bool {
	count, err := global.RDb.Exists(ctx, key).Result()
	if err != nil {
		return false
	}
	// `count > 0` means the key exists
	return count > 0
}

func Delete(key string) error {
	err := global.RDb.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	return nil
}

func Get(key string, result interface{}) error {
	value, err := global.RDb.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("key %s does not exist", key)
		}

		return fmt.Errorf("failed to get value: %w", err)
	}

	err = json.Unmarshal([]byte(value), result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal value into result: %w", err)
	}

	return nil
}

func GetTTL(key string) (time.Duration, error) {
	timeRemaining, err := global.RDb.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("error checking TTL: %v", err)
	}

	switch {
	case timeRemaining == -2:
		return 0, fmt.Errorf("key does not exist")
	case timeRemaining == -1:
		return 0, fmt.Errorf("key exists but has no expiration")
	case timeRemaining > 0:
		return timeRemaining, nil
	default:
		return 0, fmt.Errorf("unexpected TTL value")
	}
}
