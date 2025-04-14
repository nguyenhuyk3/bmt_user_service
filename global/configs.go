package global

import (
	"user_service/pkgs/loggers"
	"user_service/pkgs/settings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

var (
	Config     settings.Config
	Postgresql *pgxpool.Pool
	RDb        *redis.Client
	Logger     *loggers.LoggerZap
	// Queries    *sqlc.Queries
)

type GoogleOAuthConfig *oauth2.Config
type FacebookOAuthConfig *oauth2.Config
