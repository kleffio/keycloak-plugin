# idp-keycloak

Kleff IDP plugin for [Keycloak](https://www.keycloak.org/).

Implements the `IdentityPlugin` and `PluginHealth` gRPC services from
`platform/api/plugins/v1/` and exposes them on port `50051` (configurable via
`PLUGIN_PORT`).

---

## Quick Start (Local Dev)

```bash
# 1. Start a local Keycloak instance on the kleff Docker network
docker network create kleff 2>/dev/null || true

docker run -d \
  --name keycloak \
  --network kleff \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -p 8080:8080 \
  quay.io/keycloak/keycloak:25.0 start-dev

# 2. Build the plugin (run from the repo root — Dockerfile needs the plugin-sdk context)
docker build \
  --build-context plugin-sdk=../../plugin-sdk \
  -f plugins/idp-keycloak/Dockerfile \
  -t kleff/idp-keycloak:dev \
  .

# 3. Run the plugin
docker run -d \
  --name kleff-idp-keycloak \
  --network kleff \
  -e KEYCLOAK_URL=http://keycloak:8080 \
  -e KEYCLOAK_REALM=master \
  -e KEYCLOAK_CLIENT_ID=admin-cli \
  -e KEYCLOAK_ADMIN_USER=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  kleff/idp-keycloak:dev

# 4. Health check
grpcurl -plaintext localhost:50051 kleff.plugins.v1.PluginHealth/Health

# 5. Install via the Kleff API (requires the platform to be running)
curl -X POST http://localhost:8080/api/v1/admin/plugins \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "idp-keycloak",
    "version": "1.0.0",
    "config": {
      "KEYCLOAK_URL": "http://keycloak:8080",
      "KEYCLOAK_REALM": "master",
      "KEYCLOAK_CLIENT_ID": "admin-cli",
      "KEYCLOAK_ADMIN_USER": "admin",
      "KEYCLOAK_ADMIN_PASSWORD": "admin"
    }
  }'

# 6. Set as the active IDP
curl -X POST http://localhost:8080/api/v1/admin/plugins/idp-keycloak/set-active \
  -H "Authorization: Bearer <admin-token>"

# 7. Test login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

---

## Environment Variables

| Variable                  | Required | Default        | Description                                                               |
|---------------------------|----------|----------------|---------------------------------------------------------------------------|
| `KEYCLOAK_URL`            | **Yes**  | —              | Internal (server-to-server) Keycloak root URL, e.g. `http://keycloak:8080` |
| `KEYCLOAK_PUBLIC_URL`     | No       | `KEYCLOAK_URL` | Browser-reachable URL returned in OIDC config. Set this when your internal and public URLs differ. |
| `KEYCLOAK_REALM`          | No       | `master`       | Keycloak realm name                                                       |
| `KEYCLOAK_CLIENT_ID`      | No       | `kleff-panel`  | Client ID. Use a confidential client with **Direct Access Grants** enabled. |
| `KEYCLOAK_CLIENT_SECRET`  | No       | —              | Client secret (required for confidential clients)                         |
| `KEYCLOAK_ADMIN_USER`     | No       | `admin`        | Admin username used to obtain an admin token for user registration        |
| `KEYCLOAK_ADMIN_PASSWORD` | No       | —              | Admin password                                                            |
| `AUTH_MODE`               | No       | `headless`     | `headless` — users log in via the Kleff panel form. `redirect` — users are redirected to the Keycloak login page via OIDC Authorization Code flow. |
| `PLUGIN_PORT`             | No       | `50051`        | gRPC listen port                                                          |

---

## Authentication Modes

### `headless` (default)

Users enter their credentials in the Kleff panel login form. The plugin authenticates
them via Keycloak's **Direct Access Grant** (Resource Owner Password Credentials flow):

```
Panel → POST /api/v1/auth/login → Platform → gRPC Login() → Keycloak token endpoint
```

The Keycloak client must have **Direct Access Grants** enabled.

### `redirect`

Users are redirected to the Keycloak login page. The platform acts as an OIDC
relying party, using the **Authorization Code** flow. The plugin exposes its OIDC
discovery config via the `GetOIDCConfig` RPC, which the panel uses to build the
redirect URL and validate the returned ID token.

---

## gRPC RPCs Implemented

| Service          | RPC              | Description                                               |
|------------------|------------------|-----------------------------------------------------------|
| `PluginHealth`   | `Health`         | Returns `HEALTHY`. Called by the platform every 30s.      |
| `PluginHealth`   | `GetCapabilities`| Returns `identity.provider` and `ui.manifest`.           |
| `IdentityPlugin` | `Login`          | Authenticates via Direct Access Grant. Returns token set. |
| `IdentityPlugin` | `Register`       | Creates a user via the Keycloak Admin REST API.           |
| `IdentityPlugin` | `GetUser`        | Not supported — returns `NOT_SUPPORTED`.                  |
| `IdentityPlugin` | `ValidateToken`  | Verifies an RS256 JWT against Keycloak's JWKS endpoint.  |
| `IdentityPlugin` | `GetOIDCConfig`  | Returns OIDC discovery parameters for the panel.          |
| `IdentityPlugin` | `RefreshToken`   | Exchanges a refresh token for a new token set.            |
| `PluginUI`       | `GetUIManifest`  | Returns a settings page linking to the Keycloak admin UI. |

---

## Internal Architecture

The plugin follows hexagonal architecture (ports and adapters):

```
cmd/plugin/main.go
  │
  ├── adapters/keycloak/     (outbound adapter)
  │     client.go            HTTP client for Keycloak token and admin endpoints
  │     jwks.go              RS256 JWT verification with 5-minute JWKS cache
  │
  ├── core/ports/
  │     provider.go          IDPProvider interface (the boundary)
  │
  ├── core/domain/
  │     types.go             TokenSet, TokenClaims, OIDCConfig, RegisterRequest
  │     errors.go            ErrUnauthorized, ErrConflict (typed sentinel errors)
  │
  ├── core/application/
  │     service.go           Thin use-case layer; delegates to IDPProvider
  │
  └── adapters/grpc/
        server.go            Inbound gRPC adapter; translates proto ↔ domain types
```

### Dependency direction

```
grpc/server → application/service → ports/IDPProvider ← keycloak/Client
```

The Keycloak HTTP client only knows about domain types. The gRPC adapter only
knows about the application service. Neither layer leaks its concerns into the other.

### JWKS Token Validation

`ValidateToken` verifies JWTs locally without a round-trip to Keycloak for every
request:

1. Parse the JWT header to extract `kid` (key ID) and verify `alg == RS256`.
2. Look up the RSA public key by `kid` in the in-process cache.
3. If cache is empty or stale (> 5 minutes), fetch
   `GET /realms/{realm}/protocol/openid-connect/certs` and repopulate.
4. Verify the PKCS1v15 signature against SHA-256 of `header.payload`.
5. Decode claims — check `sub` is present and `exp` has not passed.
6. Return `TokenClaims{Subject, Email, Roles}` (merged from `roles` and `realm_access.roles`).

### User Registration

Registration uses the Keycloak Admin REST API:

1. Obtain an admin access token from the `master` realm using
   `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASSWORD`.
2. `POST /admin/realms/{realm}/users` with the user payload.
3. On `201 Created`, extract the new user ID from the `Location` response header.
4. On `409 Conflict`, return `ErrConflict`.

---

## Keycloak Setup

### Minimum Keycloak configuration

1. Create a realm (e.g. `kleff`) or use `master` for testing.
2. Create a client:
   - **Client ID:** `kleff-panel` (or your chosen value)
   - **Client authentication:** On (confidential)
   - **Authentication flows → Direct access grants:** Enabled (for `headless` mode)
3. Copy the client secret into `KEYCLOAK_CLIENT_SECRET`.
4. For user registration, provide admin credentials in
   `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASSWORD`.

### Recommended realm settings

- Enable **email as username** if your users log in with email addresses.
- Configure SMTP for password reset emails.
- Set token lifetimes appropriate for your use case (access token: 5–15 min,
  refresh token: 24–168 h).

---

## Building

The Dockerfile uses a two-stage build. It must be run from the repo root because
it needs both `plugin-sdk/` and `plugins/idp-keycloak/` in the build context:

```bash
# From repo root
docker build \
  -f plugins/idp-keycloak/Dockerfile \
  -t ghcr.io/kleffio/idp-keycloak:1.0.0 \
  .
```

The final image is based on `alpine:3.20` and contains only the statically
linked plugin binary and CA certificates. Image size is typically under 20 MB.
