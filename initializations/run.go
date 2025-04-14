package initializations

import (
	"fmt"
	"user_service/global"
)

func Run() {
	loadConfigs()
	initLogger()
	initRedis()
	initPostgreSql()

	r := initRouter()

	r.Run(fmt.Sprintf("localhost:%s", global.Config.Server.ServerPort))
}
