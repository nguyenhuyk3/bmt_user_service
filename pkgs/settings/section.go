package settings

type Config struct {
	Server     serverSetting
	PostgreSql postgreSetting
}

type serverSetting struct {
	ServiceName      string `mapstructure:"SERVICE_NAME"`
	ConfigServiceUrl string `mapstructure:"CONFIG_SERVICE_URL"`
	APIKey           string `mapstructure:"API_KEY"`
}

type postgreSetting struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Dbname          string `json:"dbname"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	MaxOpenConns    int    `json:"max_open_conns"`
	ConnMaxLifetime int    `json:"conn_max_lifetime"`
}
