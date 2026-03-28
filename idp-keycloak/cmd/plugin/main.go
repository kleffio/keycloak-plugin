// Command plugin is the entrypoint for the idp-keycloak Kleff plugin.
// It wires the hexagonal layers together and starts the gRPC server.
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	pluginsv1 "github.com/kleffio/plugin-sdk/v1"
	grpcadapter "github.com/kleffio/idp-keycloak/internal/adapters/grpc"
	"github.com/kleffio/idp-keycloak/internal/adapters/keycloak"
	"github.com/kleffio/idp-keycloak/internal/core/application"
	"google.golang.org/grpc"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// ── Infrastructure (outbound adapter) ─────────────────────────────────────
	provider := keycloak.New(keycloak.Config{
		BaseURL:       mustEnv("KEYCLOAK_URL"),
		PublicBaseURL: env("KEYCLOAK_PUBLIC_URL", ""),
		Realm:         env("KEYCLOAK_REALM", "master"),
		ClientID:      env("KEYCLOAK_CLIENT_ID", "kleff-panel"),
		ClientSecret:  env("KEYCLOAK_CLIENT_SECRET", ""),
		AdminUser:     env("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPassword: env("KEYCLOAK_ADMIN_PASSWORD", ""),
		AuthMode:      env("AUTH_MODE", "headless"),
	})

	// ── Application layer ──────────────────────────────────────────────────────
	svc := application.New(provider)

	// ── Inbound adapter (gRPC) ─────────────────────────────────────────────────
	srv := grpcadapter.New(svc)

	gs := grpc.NewServer()
	pluginsv1.RegisterIdentityPluginServer(gs, srv)
	pluginsv1.RegisterPluginHealthServer(gs, srv)
	pluginsv1.RegisterPluginUIServer(gs, srv)

	port := env("PLUGIN_PORT", "50051")
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}

	go func() {
		logger.Info("plugin listening", "port", port)
		if err := gs.Serve(lis); err != nil {
			logger.Error("gRPC server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	logger.Info("shutting down")
	gs.GracefulStop()
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "required env var %s is not set\n", key)
		os.Exit(1)
	}
	return v
}
