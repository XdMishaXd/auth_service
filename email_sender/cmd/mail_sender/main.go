package main

import (
	"os"

	"email_sender/internal/config"
	"email_sender/internal/logger"
)

func main() {
	cfg := config.MustLoad()
	log := logger.MustSetup(cfg.Env)

	log.Info("starting email_sender")

	if err := run(cfg, log); err != nil {
		log.Error("app stopped with error", "error", err)
		os.Exit(1)
	}
}
