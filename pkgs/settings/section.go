package settings

type Config struct {
	Server         serverSetting
	ServiceSetting serviceSetting `json:"data"`
}

type serviceSetting struct {
	PostgreSql   postgreSetting `json:"database"`
	MailSetting  mailSetting    `json:"mail"`
	RedisSetting redisSetting   `json:"redis"`
}

type basicSetting struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Database int    `json:"database,omitempty"`
}

type serverSetting struct {
	ServiceName      string `mapstructure:"SERVICE_NAME"`
	ConfigServiceUrl string `mapstructure:"CONFIG_SERVICE_URL"`
	APIKey           string `mapstructure:"API_KEY"`
	SercetKey        string `mapstructure:"SERCET_KEY"`
	ServerPort       string `mapstructure:"SERVER_PORT"`
	LengthOfSalt     int    `mapstructure:"LENGTH_OF_SALT"`
	FromEmail        string `mapstructure:"FROM_EMAIL"`
}

type postgreSetting struct {
	BasicSetting    basicSetting `json:"basic_settings"`
	DbName          string       `json:"db_name"`
	MaxIdleConns    int          `json:"max_idle_conns"`
	MaxOpenConns    int          `json:"max_open_conns"`
	ConnMaxLifetime int          `json:"conn_max_lifetime"`
}

type mailSetting struct {
	BasicSetting basicSetting `json:"basic_settings"`
}

type redisSetting struct {
	BasicSetting basicSetting `json:"basic_settings"`
}
