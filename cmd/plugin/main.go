// Command plugin is the entrypoint for the idp-keycloak Kleff plugin.
// It wires the hexagonal layers together and starts the gRPC server.
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	pluginsv1 "github.com/kleffio/plugin-sdk-go/v1"
	grpcadapter "github.com/kleffio/idp-keycloak/internal/adapters/grpc"
	"github.com/kleffio/idp-keycloak/internal/adapters/keycloak"
	"github.com/kleffio/idp-keycloak/internal/core/application"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// ── Infrastructure (outbound adapter) ─────────────────────────────────────
	// Defaults match the bundled Keycloak companion container (id: "keycloak").
	// Override via env vars to connect to an external Keycloak instead.
	provider := keycloak.New(keycloak.Config{
		BaseURL:       env("KEYCLOAK_URL", "http://keycloak:8080"),
		PublicBaseURL: env("KEYCLOAK_PUBLIC_URL", ""),
		Realm:         env("KEYCLOAK_REALM", "kleff"),
		ClientID:      env("KEYCLOAK_CLIENT_ID", "kleff-panel"),
		ClientSecret:  env("KEYCLOAK_CLIENT_SECRET", ""),
		AdminUser:     env("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPassword: env("KEYCLOAK_ADMIN_PASSWORD", "admin"),
		AuthMode:      env("AUTH_MODE", "headless"),
		PanelURL:      env("PANEL_URL", ""),
	})

	// ── Ensure Keycloak realm is configured (retry until Keycloak is ready) ───
	setupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for {
		if err := provider.EnsureRealm(setupCtx); err == nil {
			break
		} else {
			logger.Warn("waiting for Keycloak to be ready...", "error", err)
		}
		select {
		case <-setupCtx.Done():
			logger.Error("timed out waiting for Keycloak to be ready")
			os.Exit(1)
		case <-time.After(5 * time.Second):
		}
	}

	// ── Application layer ──────────────────────────────────────────────────────
	svc := application.New(provider)

	// ── Inbound adapter (gRPC) ─────────────────────────────────────────────────
	srv := grpcadapter.New(svc)

	var serverOpts []grpc.ServerOption
	if certPEM := env("PLUGIN_TLS_CERT_PEM", ""); certPEM != "" {
		keyPEM := env("PLUGIN_TLS_KEY_PEM", "")
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			logger.Error("invalid TLS cert/key", "error", err)
			os.Exit(1)
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
		})))
		logger.Info("gRPC server configured with mTLS")
	}

	gs := grpc.NewServer(serverOpts...)
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

