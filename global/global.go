package global

import (
	"user_service/db/sqlc"
	"user_service/pkgs/settings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var (
	Config     settings.Config
	Postgresql *pgxpool.Pool
	RDb        *redis.Client
	Queries    *sqlc.Queries
)

const (
	OTP_KEY                       = "opt::"
	COMPLETE_REGISTRATION_PROCESS = "complete_registration_process::"
)
