package initializations

import (
	"context"
	"fmt"
	"user_service/global"

	"github.com/jackc/pgx/v5/pgxpool"
)

func initPostgreSql() {
	config := global.Config.ServiceSetting.PostgreSql.BasicSetting
	dbName := global.Config.ServiceSetting.PostgreSql.DbName
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host, config.Port, config.Username, config.Password, dbName)
	ctx := context.Background()
	db, err := pgxpool.New(ctx, connStr)
	if err != nil {
		fmt.Println("error connecting to the database:", err)
		return
	}
	defer db.Close()

	if err := db.Ping(ctx); err != nil {
		fmt.Println("error pinging the database:", err)
		return
	}

	fmt.Println("successfully connected to the database")

	global.Postgresql = db
}
