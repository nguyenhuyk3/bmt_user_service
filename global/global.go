package global

import (
	"database/sql"
	"user_service/pkgs/settings"

	"github.com/redis/go-redis/v9"
)

var (
	Config     settings.Config
	Postgresql *sql.DB
	RDb        *redis.Client
)
