package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auth_service/internal/config"

	"github.com/go-chi/chi/v5"
)

func newHTTPServer(cfg *config.Config, mux *chi.Mux) *http.Server {
	return &http.Server{
		Addr:         cfg.HTTPServer.Address,
		Handler:      mux,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}
}

// run запускает сервер, ждёт либо ошибку сервера, либо сигнал ОС,
// и в обоих случаях выполняет graceful shutdown + cleanup ресурсов.
func run(srv *http.Server, cleanup cleanupFunc, log *slog.Logger) {
	serverErrors := make(chan error, 1)
	go func() {
		log.Info("starting http server", slog.String("address", srv.Addr))
		serverErrors <- srv.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Error("server error", slog.String("error", err.Error()))
		cleanup(log) // без этого - утечка соединений даже при чистом старте, если сервер упал позже

	case sig := <-shutdown:
		log.Info("shutdown signal received", slog.String("signal", sig.String()))

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("failed to shutdown server gracefully", slog.String("error", err.Error()))
			if closeErr := srv.Close(); closeErr != nil {
				log.Error("failed to force close server", slog.String("error", closeErr.Error()))
			}
		}

		cleanup(log)
		log.Info("server stopped gracefully")
	}
}
