package initializations

import (
	"fmt"
	"log"
	"user_service/global"

	"github.com/spf13/viper"
)

func loadConfigs() {
	loadConfigsFromENV()
	loadConfigsFromYAML()
}

func loadConfigsFromENV() {
	viper.AddConfigPath(".")
	viper.SetConfigName("app")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("error loading .env file")
	}

	err = viper.Unmarshal(&global.Config.Server)
	if err != nil {
		log.Fatalf("unable to decode into struct (env), %v", err)
	}

	fmt.Println(global.Config.Server.FixedIv)
}

func loadConfigsFromYAML() {
	viper.AddConfigPath(".")
	viper.SetConfigName("local")
	viper.SetConfigType("yaml")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("error loading .yaml file")
	}

	err = viper.Unmarshal(&global.Config.ServiceSetting)
	if err != nil {
		log.Fatalf("unable to decode into struct (yaml), %v", err)
	}
}
