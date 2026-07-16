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
	Username string `yaml:"username" env-default:"admin"`
	Password string `yaml:"password" env-default:"admin"`
	Enabled  bool   `yaml:"enabled" env-default:"false"`
}

type HTTPServer struct {
	Address         string        `yaml:"address" env-default:"localhost:8080"`
	Timeout         time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout     time.Duration `yaml:"idle_timeout" env-default:"60s"`
	HandlersTimeout time.Duration `yaml:"handlers_timeout" env-default:"5s"`
}

type OAuth struct {
	StateTTL             time.Duration       `yaml:"state_ttl" env-default:"5m"`
	HandlersTimeout      time.Duration       `yaml:"handlers_timeout" env-default:"10s"`
	AllowedRedirectHosts []string            `yaml:"allowed_redirect_hosts" env-required:"true"`
	Google               OAuthProviderConfig `yaml:"google"`
	GitHub               OAuthProviderConfig `yaml:"github"`
}

type OAuthProviderConfig struct {
	ClientID     string `yaml:"client_id" env-required:"true"`
	ClientSecret string `yaml:"client_secret" env-required:"true"`
	RedirectURL  string `yaml:"redirect_url" env-required:"true"`
}

type TwoFactorAuth struct {
	TokenTTL          time.Duration `yaml:"token_ttl" env-default:"10m"`
	TokenSecret       string        `yaml:"token_secret" env-required:"true"`
	RedirectURL       string        `yaml:"redirect_url" env-default:"http://localhost:8082"`
	PendingSessionTTL time.Duration `yaml:"pending_session_ttl" env-default:"10m"`
}

type Postgres struct {
	Host     string `yaml:"host" env-default:"postgres"`
	Port     int    `yaml:"port" env-default:"5432"`
	User     string `yaml:"user" env-required:"true"`
	Password string `yaml:"password" env-required:"true"`
	DBName   string `yaml:"dbname" env-required:"true"`
	SSLMode  string `yaml:"sslmode" env-default:"disabled"`
}

type Redis struct {
	Addr     string `yaml:"addr" env-default:"redis:6379"`
	Password string `yaml:"password" env-required:"true"`
	Db       int    `yaml:"db" env-default:"1"`
}

type Tokens struct {
	AccessTokenTTL          time.Duration `yaml:"access_token_ttl" env-required:"true"`
	RefreshTokenTTL         time.Duration `yaml:"refresh_token_ttl" env-required:"true"`
	VerificationTokenTTL    time.Duration `yaml:"verification_token_ttl" env-default:"15m"`
	ResetTokenTTL           time.Duration `yaml:"reset_token_ttl" env-default:"15m"`
	VerificationTokenSecret string        `yaml:"verification_token_secret" env-required:"true"`
}

type RabbitMQ struct {
	URL       string `yaml:"url" env-required:"true"`
	QueueName string `yaml:"queue_name" env-required:"true"`
}

func MustLoad(configPath string) *Config {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("Config file does not exist" + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("Failed to read config" + err.Error())
	}

	return &cfg
}
