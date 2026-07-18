package config

import (
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env           string `yaml:"env" env-default:"local"`
	Tokens        `yaml:"tokens"`
	RabbitMQ      `yaml:"rabbitmq"`
	Postgres      `yaml:"postgres"`
	Redis         `yaml:"redis"`
	HTTPServer    `yaml:"http_server"`
	TwoFactorAuth `yaml:"two_factor_auth"`
	Swagger       `yaml:"swagger"`
	OAuth         `yaml:"oauth"`
}

type Swagger struct {
	Username string `yaml:"username" env:"SWAGGER_USERNAME" env-default:"admin"`
	Password string `yaml:"password" env:"SWAGGER_PASSWORD" env-default:"admin"`
	Enabled  bool   `yaml:"enabled" env-default:"false"`
}

type HTTPServer struct {
	Address         string        `yaml:"address" env-default:"localhost:8080"`
	Timeout         time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout     time.Duration `yaml:"idle_timeout" env-default:"60s"`
	HandlersTimeout time.Duration `yaml:"handlers_timeout" env-default:"5s"`
}

type OAuth struct {
	StateTTL             time.Duration `yaml:"state_ttl" env-default:"5m"`
	HandlersTimeout      time.Duration `yaml:"handlers_timeout" env-default:"10s"`
	AllowedRedirectHosts []string      `yaml:"allowed_redirect_hosts" env-default:"localhost"`

	GoogleClientID     string `yaml:"-" env:"GOOGLE_CLIENT_ID" env-required:"true"`
	GoogleClientSecret string `yaml:"-" env:"GOOGLE_CLIENT_SECRET" env-required:"true"`
	GoogleRedirectURL  string `yaml:"-" env:"GOOGLE_REDIRECT_URL" env-required:"true"`

	GitHubClientID     string `yaml:"-" env:"GITHUB_CLIENT_ID" env-required:"true"`
	GitHubClientSecret string `yaml:"-" env:"GITHUB_CLIENT_SECRET" env-required:"true"`
	GitHubRedirectURL  string `yaml:"-" env:"GITHUB_REDIRECT_URL" env-required:"true"`
}

type TwoFactorAuth struct {
	TokenTTL          time.Duration `yaml:"token_ttl" env-default:"10m"`
	TokenSecret       string        `yaml:"-" env:"TWO_FACTOR_TOKEN_SECRET" env-required:"true"`
	RedirectURL       string        `yaml:"redirect_url" env-default:"http://localhost:8082"`
	PendingSessionTTL time.Duration `yaml:"pending_session_ttl" env-default:"10m"`
}

type Postgres struct {
	Host     string `yaml:"host" env-default:"postgres"`
	Port     int    `yaml:"port" env-default:"5432"`
	User     string `yaml:"-" env:"POSTGRES_USER" env-required:"true"`
	Password string `yaml:"-" env:"POSTGRES_PASSWORD" env-required:"true"`
	DBName   string `yaml:"-" env:"POSTGRES_DB" env-required:"true"`
	SSLMode  string `yaml:"sslmode" env-default:"disable"`
}

type Redis struct {
	Addr     string `yaml:"addr" env-default:"redis:6379"`
	Password string `yaml:"-" env:"REDIS_PASSWORD" env-required:"true"`
	Db       int    `yaml:"db" env-default:"1"`
}

type Tokens struct {
	AccessTokenTTL          time.Duration `yaml:"access_token_ttl" env-default:"1h"`
	RefreshTokenTTL         time.Duration `yaml:"refresh_token_ttl" env-default:"168h"`
	VerificationTokenTTL    time.Duration `yaml:"verification_token_ttl" env-default:"15m"`
	ResetTokenTTL           time.Duration `yaml:"reset_token_ttl" env-default:"15m"`
	VerificationTokenSecret string        `yaml:"-" env:"VERIFICATION_TOKEN_SECRET" env-required:"true"`
}

type RabbitMQ struct {
	URL       string `yaml:"-" env:"RABBITMQ_URL" env-required:"true"`
	QueueName string `yaml:"queue_name" env-default:"notificationsQueue"`
}

func MustLoad(configPath string) *Config {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("Config file does not exist: " + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("Failed to read config: " + err.Error())
	}

	return &cfg
}
