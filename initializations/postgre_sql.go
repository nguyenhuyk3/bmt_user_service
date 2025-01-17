package initializations

import (
	"database/sql"
	"fmt"
	"user_service/global"

	_ "github.com/lib/pq"
)

func initPostgreSql() {
	config := global.Config.ServiceSetting.PostgreSql.BasicSetting
	dbName := global.Config.ServiceSetting.PostgreSql.DbName
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		config.Host, config.Port, config.Username, config.Password, dbName)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		fmt.Println("error connecting to the database (initPostgresql):", err)
		return
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fmt.Println("error pinging the database:", err)
		return
	}

	fmt.Println("Successfully connected to the database")

	global.Postgresql = db
}
