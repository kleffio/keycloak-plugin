package keycloak

import (
	"context"

	"github.com/kleffio/idp-keycloak/internal/core/domain"
)

// ValidateToken verifies an RS256 JWT against Keycloak's JWKS endpoint.
// Verification and key caching is handled by the per-instance JWTValidator
// on the Client, which also enforces session revocations registered via
// RevokeSession.
func (c *Client) ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error) {
	claims, err := c.validator.ValidateToken(ctx, rawToken)
	if err != nil {
		return nil, &domain.ErrUnauthorized{Msg: err.Error()}
	}
	return &domain.TokenClaims{
		Subject: claims.Subject,
		Email:   claims.Email,
		Roles:   claims.Roles,
	}, nil
}
