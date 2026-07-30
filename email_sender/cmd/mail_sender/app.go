package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"email_sender/internal/config"
	emailhandler "email_sender/internal/email_handler"
	"email_sender/internal/mailer"
	"email_sender/internal/metrics"
	"email_sender/internal/rabbitmq"
	"email_sender/internal/router"
)

func run(cfg *config.Config, log *slog.Logger) error {
	m := metrics.New()

	rabbitMQClient, err := rabbitmq.New(cfg.RabbitMQ.URL, m, log)
	if err != nil {
		return fmt.Errorf("connect rabbitmq: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := rabbitMQClient.Close(closeCtx); err != nil {
			log.Error("close rabbitmq", slog.String("error", err.Error()))
		}
	}()
	log.Info("rabbitmq connected successfully")

	mailSender := mailer.NewMailer(
		cfg.Email.Host,
		cfg.Email.Port,
		cfg.MailerPoolSize,
		cfg.Email.Username,
		cfg.Email.Password,
		log,
	)
	defer func() {
		if err := mailSender.Close(); err != nil {
			log.Error("close mailer", slog.String("error", err.Error()))
		}
	}()

	handler := emailhandler.New(log, mailSender, cfg)
	rtr := router.SetupRouter(m)

	srv := &http.Server{
		Addr:         cfg.HTTPServer.Address,
		Handler:      rtr,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	consumerCtx, consumerCancel := context.WithCancel(context.Background())
	defer consumerCancel()

	serverErrors := make(chan error, 1)
	go func() {
		log.Info("starting http server", slog.String("address", cfg.HTTPServer.Address))
		serverErrors <- srv.ListenAndServe()
	}()

	consumerErrors := make(chan error, 1)
	go func() {
		log.Info("starting rabbitmq consumer", slog.String("queue", cfg.RabbitMQ.QueueName))
		consumerErrors <- rabbitMQClient.StartReading(consumerCtx, cfg.RabbitMQ.QueueName, handler.Handle)
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		consumerCancel()
		return fmt.Errorf("server error: %w", err)

	case err := <-consumerErrors:
		log.Error("consumer error", slog.String("error", err.Error()))

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if srvErr := srv.Shutdown(shutdownCtx); srvErr != nil {
			log.Error("failed to shutdown http server", slog.String("error", srvErr.Error()))
		}
		return fmt.Errorf("consumer error: %w", err)

	case sig := <-shutdown:
		log.Info("shutdown signal received", slog.String("signal", sig.String()))
		consumerCancel()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		log.Info("shutting down http server")
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("failed to shutdown server gracefully", slog.String("error", err.Error()))
			if closeErr := srv.Close(); closeErr != nil {
				log.Error("failed to force close server", slog.String("error", closeErr.Error()))
			}
		}

		log.Info("server stopped gracefully")
		return nil
	}
}
