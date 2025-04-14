package settings

type Config struct {
	Server         serverSetting
	ServiceSetting serviceSetting
}

type serviceSetting struct {
	PostgreSql     postgreSetting `mapstructure:"database"`
	MailSetting    mailSetting    `mapstructure:"mail"`
	RedisSetting   redisSetting   `mapstructure:"redis"`
	KafkaSetting   kafkaSetting   `mapstructure:"kafka"`
	GoogleOAuth2   googleOAuth2   `mapstructure:"google_oauth_2"`
	FacebookOAuth2 facebookOAuth2 `mapstructure:"facebook_oauth_2"`
	LoggerSetting  LoggerSetting  `mapstructure:"zap_log"`
}

type serverSetting struct {
	ServerPort   string `mapstructure:"SERVER_PORT"`
	FromEmail    string `mapstructure:"FROM_EMAIL"`
	SercetKey    string `mapstructure:"SERCET_KEY"`
	LengthOfSalt int    `mapstructure:"LENGTH_OF_SALT"`
	Issuer       string `mapstructure:"ISS"`
	FixedIv      string `mapstructure:"FIXED_IV"`
}

type postgreSetting struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	Username        string `mapstructure:"username,omitempty"`
	Password        string `mapstructure:"password,omitempty"`
	DbName          string `mapstructure:"db_name"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	ConnMaxLifetime int    `mapstructure:"conn_max_lifetime"`
}

type mailSetting struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username,omitempty"`
	Password string `mapstructure:"password,omitempty"`
}

type redisSetting struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username,omitempty"`
	Password string `mapstructure:"password,omitempty"`
	Database int    `mapstructure:"database,omitempty"`
}

type kafkaSetting struct {
	KafkaBroker_1 string `mapstructure:"kafka_broker_1"`
	KafkaBroker_2 string `mapstructure:"kafka_broker_2"`
	KafkaBroker_3 string `mapstructure:"kafka_broker_3"`
}

type googleOAuth2 struct {
	RedirectUrl  string `mapstructure:"redirect_url"`
	ClientId     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_sercet"`
}

type facebookOAuth2 struct {
	RedirectUrl string `mapstructure:"redirect_url"`
	AppId       string `mapstructure:"app_id"`
	AppSecret   string `mapstructure:"app_sercet"`
}

type LoggerSetting struct {
	LogLevel    string `mapstructure:"log_level"` // examples: "debug", "info", "warn", "error"
	FileLogName string `mapstructure:"file_log_name"`
	MaxBackups  int    `mapstructure:"max_backups"`
	MaxAge      int    `mapstructure:"max_age"` // number of days to keep log
	MaxSize     int    `mapstructure:"max_size"`
	Compress    bool   `mapstructure:"compress"` // compress old logs
}
