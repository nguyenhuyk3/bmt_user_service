package provider

import (
	"user_service/global"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ProvidePgxPool() *pgxpool.Pool {
	return global.Postgresql
}

func ProvideSecretKey() string {
	return global.Config.Server.SercetKey
}
