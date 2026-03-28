# Kleff Plugins

This repository contains official Kleff plugins. Each plugin is an independent
Go module, Docker image, and release cycle. Plugins communicate with the Kleff
platform exclusively over gRPC.

## Repository Layout

```
plugins/
  idp-keycloak/          ← Keycloak identity provider plugin
    kleff-plugin.json    ← plugin manifest (required by every plugin)
    Dockerfile
    README.md
    go.mod
    cmd/plugin/main.go   ← entrypoint: wires layers, starts gRPC server
    internal/
      core/
        domain/          ← pure types and domain errors (no deps)
        ports/           ← outbound interface (IDPProvider)
        application/     ← use-case service (orchestrates ports)
      adapters/
        grpc/            ← inbound: translates gRPC ↔ domain
        keycloak/        ← outbound: Keycloak HTTP client
  LICENSE
```

Each plugin directory is self-contained. Plugins may be hosted in separate repos;
this monorepo is used for official Kleff-maintained plugins.

---

## What is a Kleff Plugin?

A Kleff plugin is a standalone process that:

1. Implements one or more Kleff gRPC services (defined in `.proto` files in the
   platform repo under `platform/api/plugins/v1/`).
2. Packages itself as a Docker image.
3. Declares itself via a `kleff-plugin.json` manifest.
4. Is listed in the Kleff plugin registry or self-hosted.

The platform manages the full plugin lifecycle: pulling images, starting
containers, connecting over gRPC, persisting config, and tearing down on removal.

---

## Plugin Types

| Type  | gRPC Service      | Description                                        |
|-------|-------------------|----------------------------------------------------|
| `idp` | `IdentityPlugin`  | Identity provider — login, registration, JWT verify |

Future types: `billing`, `notifications`, `storage`, `gameruntime`, `audit`.

---

## Creating a New Plugin

### 1. Scaffold the directory

```
my-plugin/
  kleff-plugin.json
  Dockerfile
  README.md
  cmd/plugin/main.go
  internal/
    adapters/grpc/server.go
    core/application/service.go
    core/domain/types.go
    core/ports/provider.go
```

### 2. Write the manifest (`kleff-plugin.json`)

```json
{
  "id": "idp-myauth",
  "name": "MyAuth",
  "type": "idp",
  "description": "Connect Kleff to MyAuth.",
  "tags": ["sso", "enterprise"],
  "author": "Your Name",
  "repo": "https://github.com/you/idp-myauth",
  "image": "ghcr.io/you/idp-myauth",
  "version": "1.0.0",
  "minKleffVersion": "0.5.0",
  "license": "MIT",
  "verified": false,
  "capabilities": ["identity.provider"],
  "config": [
    {
      "key": "MYAUTH_DOMAIN",
      "label": "Domain",
      "type": "string",
      "required": true
    },
    {
      "key": "MYAUTH_CLIENT_SECRET",
      "label": "Client Secret",
      "type": "secret",
      "required": true
    }
  ]
}
```

**Manifest field reference:**

| Field             | Type       | Required | Description                                            |
|-------------------|------------|----------|--------------------------------------------------------|
| `id`              | string     | Yes      | Unique identifier, kebab-case (`idp-myauth`)           |
| `name`            | string     | Yes      | Human-readable display name                           |
| `type`            | string     | Yes      | Plugin type (`idp`, etc.)                             |
| `description`     | string     | Yes      | Short one-line description                            |
| `longDescription` | string     | No       | Markdown shown in the marketplace detail view         |
| `tags`            | string[]   | No       | Searchable tags (`sso`, `enterprise`, `self-hosted`)  |
| `author`          | string     | Yes      | Author name or org                                    |
| `repo`            | string     | Yes      | URL to the public source repo                         |
| `image`           | string     | Yes      | Docker image reference (without tag)                  |
| `version`         | string     | Yes      | Semantic version of this manifest                     |
| `minKleffVersion` | string     | No       | Minimum compatible Kleff platform version             |
| `license`         | string     | Yes      | SPDX license identifier (`MIT`, `Apache-2.0`, etc.)  |
| `verified`        | bool       | Yes      | `true` only for Kleff-audited plugins                 |
| `capabilities`    | string[]   | No       | Capability tokens (`identity.provider`, `ui.manifest`)|
| `config`          | object[]   | No       | User-facing config fields (see below)                 |

**Config field types:** `string`, `url`, `secret`, `select`, `boolean`, `number`.
Fields with `"type": "secret"` are stored encrypted and never returned by the API.

### 3. Implement the gRPC service (Go)

IDP plugins must implement `IdentityPlugin` and `PluginHealth` from
`platform/api/plugins/v1/`. Copy the proto files into your plugin repo or
reference them via `replace` in `go.mod`.

```go
// internal/adapters/grpc/server.go
package grpc

import (
    "context"
    pluginsv1 "github.com/kleffio/plugin-sdk/v1"
    "github.com/you/idp-myauth/internal/core/application"
    "github.com/you/idp-myauth/internal/core/domain"
)

type Server struct {
    pluginsv1.UnimplementedIdentityPluginServer
    pluginsv1.UnimplementedPluginHealthServer
    svc *application.Service
}

func New(svc *application.Service) *Server { return &Server{svc: svc} }

func (s *Server) Health(_ context.Context, _ *pluginsv1.HealthRequest) (*pluginsv1.HealthResponse, error) {
    return &pluginsv1.HealthResponse{Status: pluginsv1.HealthStatusHealthy}, nil
}

func (s *Server) Login(ctx context.Context, req *pluginsv1.LoginRequest) (*pluginsv1.LoginResponse, error) {
    tok, err := s.svc.Login(ctx, req.Username, req.Password)
    if err != nil {
        if domain.IsUnauthorized(err) {
            return &pluginsv1.LoginResponse{
                Error: &pluginsv1.PluginError{Code: pluginsv1.ErrorCodeUnauthorized, Message: err.Error()},
            }, nil
        }
        return nil, err
    }
    return &pluginsv1.LoginResponse{
        Token: &pluginsv1.TokenSet{
            AccessToken: tok.AccessToken,
            ExpiresIn:   tok.ExpiresIn,
        },
    }, nil
}

func (s *Server) Register(ctx context.Context, req *pluginsv1.RegisterRequest) (*pluginsv1.RegisterResponse, error) {
    // Return ErrorCodeNotSupported if your provider doesn't support registration.
    return &pluginsv1.RegisterResponse{
        Error: &pluginsv1.PluginError{Code: pluginsv1.ErrorCodeNotSupported},
    }, nil
}
```

**Error mapping convention:**

| Situation              | Use                        |
|------------------------|----------------------------|
| Bad credentials        | `ErrorCodeUnauthorized`    |
| User already exists    | `ErrorCodeConflict`        |
| Feature not supported  | `ErrorCodeNotSupported`    |
| Unexpected failure     | return `nil, err` (gRPC status error) |

### 4. Wire everything in `main.go`

```go
package main

import (
    "log/slog"
    "net"
    "os"

    pluginsv1 "github.com/kleffio/plugin-sdk/v1"
    grpcadapter "github.com/you/idp-myauth/internal/adapters/grpc"
    "github.com/you/idp-myauth/internal/adapters/myauth"
    "github.com/you/idp-myauth/internal/core/application"
    "google.golang.org/grpc"
)

func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    provider := myauth.New(myauth.Config{
        Domain:       mustEnv("MYAUTH_DOMAIN"),
        ClientSecret: mustEnv("MYAUTH_CLIENT_SECRET"),
    })
    svc := application.New(provider)
    srv := grpcadapter.New(svc)

    gs := grpc.NewServer()
    pluginsv1.RegisterIdentityPluginServer(gs, srv)
    pluginsv1.RegisterPluginHealthServer(gs, srv)

    port := env("PLUGIN_PORT", "50051")
    lis, _ := net.Listen("tcp", ":"+port)
    logger.Info("plugin listening", "port", port)
    gs.Serve(lis)
}

func env(k, d string) string {
    if v := os.Getenv(k); v != "" { return v }
    return d
}

func mustEnv(k string) string {
    if v := os.Getenv(k); v != "" { return v }
    slog.Error("required env var not set", "key", k)
    os.Exit(1)
    return ""
}
```

### 5. Dockerfile

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /plugin ./cmd/plugin

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /plugin /plugin
EXPOSE 50051
ENTRYPOINT ["/plugin"]
```

### 6. Test locally

```bash
# Start your plugin
docker run --rm -p 50051:50051 \
  -e MYAUTH_DOMAIN=example.myauth.com \
  -e MYAUTH_CLIENT_SECRET=secret \
  ghcr.io/you/idp-myauth:dev

# Health check
grpcurl -plaintext localhost:50051 kleff.plugins.v1.PluginHealth/Health

# Test login
grpcurl -plaintext \
  -d '{"username":"alice@example.com","password":"hunter2"}' \
  localhost:50051 kleff.plugins.v1.IdentityPlugin/Login
```

### 7. Publish

1. Push the image: `docker push ghcr.io/you/idp-myauth:1.0.0`
2. Fork `github.com/kleff/plugin-registry`, add your manifest to `plugins.json`, open a PR.

**Registry review checklist:**
- Image is publicly pullable and has no known critical CVEs.
- `Health` RPC responds correctly.
- `required: true` fields are genuinely required.
- Secret fields use `"type": "secret"`.
- `repo` links to public source code.

---

## Platform-Injected Environment Variables

Two variables are always set by the platform, regardless of the manifest `config` schema:

| Variable      | Value                                |
|---------------|--------------------------------------|
| `PLUGIN_ID`   | Plugin `id` from the manifest        |
| `PLUGIN_PORT` | Port the plugin should listen on     |

---

## Official Plugins

| Plugin ID       | Type  | Description                        |
|-----------------|-------|------------------------------------|
| `idp-keycloak`  | `idp` | Red Hat Keycloak — self-hosted SSO |

---

## License

MIT — see [LICENSE](LICENSE).
