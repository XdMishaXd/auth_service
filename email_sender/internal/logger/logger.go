package logger

import (
	"fmt"
	"log/slog"
	"os"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func MustSetup(env string) *slog.Logger {
	log, err := setupLogger(env)
	if err != nil {
		if _, werr := fmt.Fprintf(os.Stderr, "failed to setup logger: %v\n", err); werr != nil {
			panic(1)
		}
		panic(1)
	}
	return log
}

func setupLogger(env string) (*slog.Logger, error) {
	const op = "setupLogger"

	opts := &slog.HandlerOptions{
		AddSource:   true,
		ReplaceAttr: redactSensitive,
	}

	var handler slog.Handler
	switch env {
	case envLocal:
		opts.Level = slog.LevelDebug
		handler = slog.NewTextHandler(os.Stdout, opts)
	case envDev:
		opts.Level = slog.LevelDebug
		handler = slog.NewJSONHandler(os.Stdout, opts)
	case envProd:
		opts.Level = slog.LevelInfo
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		return nil, fmt.Errorf("%s: unknown env %q", op, env)
	}

	log := slog.New(handler).With(
		slog.String("service", "auth_service"),
		slog.String("env", env),
	)

	return log, nil
}

func redactSensitive(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case "password", "token", "access_token", "refresh_token", "verifier":
		return slog.String(a.Key, "[REDACTED]")
	}
	return a
}
