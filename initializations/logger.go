package initializations

import (
	"user_service/global"
	"user_service/pkgs/loggers"
)

func initLogger() {
	global.Logger = loggers.NewLogger(global.Config.ServiceSetting.LoggerSetting)
}
