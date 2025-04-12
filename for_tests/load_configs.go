package fortests

import (
	"user_service/global"
	"user_service/utils/generator"
)

func LoadConfigsForTests() {
	global.Config.Server.FixedIv, _ = generator.GenerateStringNumberBasedOnLength(16)
}
