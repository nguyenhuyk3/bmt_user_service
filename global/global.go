package global

import (
	"user_service/pkgs/settings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var (
	Config     settings.Config
	Postgresql *pgxpool.Pool
	RDb        *redis.Client
	// Queries    *sqlc.Queries
)

const (
	REGISTRATION_OTP_KEY          = "opt::"
	COMPLETE_REGISTRATION_PROCESS = "complete_registration_process::"

	FORGOT_PASSWORD_KEY       = "forgot_password::"
	ATTEMPT_KEY               = "ettempt::"
	BLOCK_FORGOT_PASSWORD_KEY = "block_forgot_password_key::"
)

const (
	FIXED_IV = "aBcD1EfGhIjK2LmN"
)

const (
	REGISTRATION_PURPOSE    = "registration"
	FORGOT_PASSWORD_PURPOSE = "forgot_password"
)
