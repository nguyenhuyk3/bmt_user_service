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
)

// These keys below will be used for forgot password purposes
const (
	FORGOT_PASSWORD_KEY              = "forgot_password::"
	ATTEMPT_KEY                      = "ettempt::"
	BLOCK_FORGOT_PASSWORD_KEY        = "block_forgot_password_key::"
	COMPLETE_FORGOT_PASSWORD_PROCESS = "complete_forgot_password_process::"
)

const (
	REGISTRATION_PURPOSE    = "registration"
	FORGOT_PASSWORD_PURPOSE = "forgot_password"
)

const (
	BLACK_LIST = "black_list::"
)
