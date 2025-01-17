package initializations

import (
	"user_service/db/sqlc"
	"user_service/global"
)

func initSqlc() {
	queries := sqlc.New(global.Postgresql)

	global.Queries = queries
}
