package initializations

func Run() {
	loadConfigs()
	initRedis()
	initPostgreSql()
}
