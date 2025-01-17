package initializations

func Run() {
	loadConfigs()
	initRedis()
	initPostGre()
}
