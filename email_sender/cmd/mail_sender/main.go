package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"email_sender/internal/config"
	"email_sender/internal/http_server/handlers/infrastructure/health"
	metricsHandler "email_sender/internal/http_server/handlers/infrastructure/metrics"
	sl "email_sender/internal/lib/logger"
	mailer "email_sender/internal/mail-sender"
	"email_sender/internal/metrics"
	"email_sender/internal/models"
	"email_sender/internal/rabbitmq"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/sync/errgroup"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()
	log := setupLogger(cfg.Env)

	log.Info("starting email_sender", slog.String("env", cfg.Env))

	m := metrics.New()

	rabbitMQClient, err := rabbitmq.New(cfg.RabbitMQ.URL, m)
	if err != nil {
		log.Error("failed to connect rabbitmq", slog.String("err", err.Error()))
		os.Exit(1)
	}

	log.Info("rabbitmq connected successfully")

	mailSender := &mailer.Mailer{
		Host:     cfg.Email.Host,
		Port:     cfg.Email.Port,
		Username: cfg.Email.Username,
		Password: cfg.Email.Password,
	}

	router := setupRouter(m)

	srv := &http.Server{
		Addr:         cfg.HTTPServer.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	// * consumer context — отдельный от HTTP-сервера, чтобы можно было
	// затушить именно consumer при graceful shutdown, не трогая srv.Shutdown
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
		consumerErrors <- rabbitMQClient.StartReading(consumerCtx, cfg.RabbitMQ.QueueName, func(msg []byte) error {
			return handleMessage(log, mailSender, cfg, msg)
		})
	}()

	// * graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Error("server error", slog.String("error", err.Error()))
		consumerCancel()
		os.Exit(1)

	case err := <-consumerErrors:
		// consumer завершился НЕ по сигналу — это авария (например,
		// "channel closed unexpectedly" при разрыве связи с RabbitMQ)
		log.Error("consumer error", slog.String("error", err.Error()))

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if srvErr := srv.Shutdown(shutdownCtx); srvErr != nil {
			log.Error("failed to shutdown http server", slog.String("error", srvErr.Error()))
		}
		os.Exit(1)

	case sig := <-shutdown:
		log.Info("shutdown signal received", slog.String("signal", sig.String()))

		consumerCancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		log.Info("shutting down http server")

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("failed to shutdown server gracefully", slog.String("error", err.Error()))

			if closeErr := srv.Close(); closeErr != nil {
				log.Error("failed to force close server", slog.String("error", closeErr.Error()))
			}
		}

		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()

		var eg errgroup.Group

		eg.Go(func() error {
			if err := rabbitMQClient.Close(closeCtx); err != nil {
				return fmt.Errorf("rabbitmq close: %w", err)
			}
			return nil
		})

		if err := eg.Wait(); err != nil {
			log.Error("failed to close resources gracefully", slog.String("err", err.Error()))
		}

		log.Info("server stopped gracefully")
	}
}

func setupRouter(m *metrics.Metrics) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	r.Get("/health", health.New())
	r.Get("/metrics", metricsHandler.New(m))

	return r
}

func handleMessage(log *slog.Logger, mailSender *mailer.Mailer, cfg *config.Config, msg []byte) error {
	var emailMsg models.EmailMessage
	if err := json.Unmarshal(msg, &emailMsg); err != nil {
		log.Error("failed to unmarshal message", sl.Err(err))
		return fmt.Errorf("unmarshal: %w", err)
	}

	if err := mailSender.Send(
		emailMsg.Email,
		cfg.Email.Username,
		"http://localhost"+emailMsg.MessageText,
		emailMsg.Purpose,
	); err != nil {
		log.Error("failed to send message", sl.Err(err))
		return fmt.Errorf("send: %w", err)
	}

	log.Info("message sent successfully")
	return nil
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
