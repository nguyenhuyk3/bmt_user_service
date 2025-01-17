package global

import (
	"user_service/pkgs/settings"

	"github.com/redis/go-redis/v9"
)

var (
	Config settings.Config
	RDb    *redis.Client
)
