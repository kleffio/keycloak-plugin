// Package ports defines the outbound interfaces the application layer depends on.
// Concrete implementations live in internal/adapters/; tests can use mocks.
package ports

import (
	"context"

	"github.com/kleffio/idp-keycloak/internal/core/domain"
)

// IDPProvider is the outbound port through which the application talks to an
// identity provider. The Keycloak HTTP client is the production implementation.
type IDPProvider interface {
	// Login authenticates a user by username and password.
	// Returns ErrUnauthorized if the credentials are invalid.
	Login(ctx context.Context, username, password string) (*domain.TokenSet, error)

	// Register creates a new user. Returns the provider-assigned user ID.
	// Returns ErrConflict if the username or email is already taken.
	Register(ctx context.Context, req domain.RegisterRequest) (string, error)

	// ValidateToken verifies a raw JWT (RS256) and returns its claims.
	// Returns ErrUnauthorized if the token is invalid or expired.
	ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error)

	// OIDCConfig returns the static OIDC discovery parameters for this provider.
	OIDCConfig() domain.OIDCConfig

	// RefreshToken exchanges a refresh token for a new token set.
	// Returns ErrUnauthorized if the refresh token is invalid or expired.
	RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenSet, error)
}
