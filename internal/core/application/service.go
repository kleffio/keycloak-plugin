// Package application contains the use-case layer of the idp-keycloak plugin.
// It orchestrates operations using the outbound port (ports.IDPProvider) and
// returns domain types. It has no knowledge of gRPC, HTTP, or Keycloak specifics.
package application

import (
	"context"

	"github.com/kleffio/idp-keycloak/internal/core/domain"
	"github.com/kleffio/idp-keycloak/internal/core/ports"
)

// Service is the single use-case coordinator for the IDP plugin.
type Service struct {
	provider ports.IDPProvider
}

// New creates a Service backed by the given IDPProvider.
func New(provider ports.IDPProvider) *Service {
	return &Service{provider: provider}
}

// Login authenticates a user. Returns domain.ErrUnauthorized for bad credentials.
func (s *Service) Login(ctx context.Context, username, password string) (*domain.TokenSet, error) {
	return s.provider.Login(ctx, username, password)
}

// Register creates a new user. Returns domain.ErrConflict if already taken.
func (s *Service) Register(ctx context.Context, req domain.RegisterRequest) (string, error) {
	return s.provider.Register(ctx, req)
}

// ValidateToken verifies a JWT and returns its claims.
func (s *Service) ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error) {
	return s.provider.ValidateToken(ctx, rawToken)
}

// OIDCConfig returns the static OIDC discovery parameters.
func (s *Service) OIDCConfig() domain.OIDCConfig {
	return s.provider.OIDCConfig()
}

// RefreshToken exchanges a refresh token for a new token set.
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenSet, error) {
	return s.provider.RefreshToken(ctx, refreshToken)
}

// EnsureAdmin seeds the admin user and assigns the "admin" realm role.
func (s *Service) EnsureAdmin(ctx context.Context) error {
	return s.provider.EnsureAdmin(ctx)
}

// ChangePassword verifies the current password then sets the new one.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	return s.provider.ChangePassword(ctx, userID, currentPassword, newPassword)
}

// ListSessions returns all active sessions for a user.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	return s.provider.ListSessions(ctx, userID)
}

// RevokeSession revokes a specific session.
func (s *Service) RevokeSession(ctx context.Context, sessionID string) error {
	return s.provider.RevokeSession(ctx, sessionID)
}

