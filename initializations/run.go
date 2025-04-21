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

	r.Run(fmt.Sprintf("0.0.0.0:%s", global.Config.Server.ServerPort))
}
