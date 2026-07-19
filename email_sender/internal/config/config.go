package config

import (
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Env        string `yaml:"env" env:"APP_ENV" env-default:"local"`
	RabbitMQ   `yaml:"rabbitmq"`
	Email      `yaml:"email"`
	HTTPServer `yaml:"http_server"`
}

type RabbitMQ struct {
	URL       string `yaml:"-" env:"RABBITMQ_URL" env-required:"true"`
	QueueName string `yaml:"queue_name" env-default:"notificationsQueue"`
}

type HTTPServer struct {
	Address     string        `yaml:"address" env-default:"localhost:8080"`
	Timeout     time.Duration `yaml:"timeout" env-default:"4s"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`
}

type Email struct {
	Host     string `yaml:"host" env-default:"smtp.gmail.com"`
	Port     int    `yaml:"port" env-default:"587"`
	Username string `yaml:"-" env:"EMAIL_USERNAME" env-required:"true"`
	Password string `yaml:"-" env:"EMAIL_PASSWORD" env-required:"true"`
}

func MustLoad() *Config {
	configPath := "./config/config.yaml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic(fmt.Sprintf("config file does not exist: %s", configPath))
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic(fmt.Sprintf("failed to read config: %s", err))
	}

	return &cfg
}
