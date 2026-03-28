package keycloak

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kleffio/idp-keycloak/internal/core/domain"
)

var (
	jwksMu   sync.RWMutex
	jwksKeys = map[string]*rsa.PublicKey{}
	jwksTTL  time.Time
)

const jwksCacheDuration = 5 * time.Minute

// ValidateToken verifies an RS256 JWT against Keycloak's JWKS endpoint.
// Keys are cached for 5 minutes; a cache miss triggers one re-fetch.
func (c *Client) ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, &domain.ErrUnauthorized{Msg: "malformed JWT"}
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, &domain.ErrUnauthorized{Msg: "invalid JWT header"}
	}
	if header.Alg != "RS256" {
		return nil, &domain.ErrUnauthorized{Msg: fmt.Sprintf("unsupported algorithm %q", header.Alg)}
	}

	key, err := c.getKey(ctx, header.Kid)
	if err != nil {
		return nil, &domain.ErrUnauthorized{Msg: err.Error()}
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &domain.ErrUnauthorized{Msg: "invalid JWT signature encoding"}
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sigBytes); err != nil {
		return nil, &domain.ErrUnauthorized{Msg: "invalid JWT signature"}
	}

	var claims struct {
		Sub         string   `json:"sub"`
		Email       string   `json:"email"`
		Exp         int64    `json:"exp"`
		Roles       []string `json:"roles"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, &domain.ErrUnauthorized{Msg: "invalid JWT claims"}
	}
	if claims.Sub == "" {
		return nil, &domain.ErrUnauthorized{Msg: "missing sub claim"}
	}
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, &domain.ErrUnauthorized{Msg: "token expired"}
	}

	roles := append(claims.Roles, claims.RealmAccess.Roles...)
	return &domain.TokenClaims{Subject: claims.Sub, Email: claims.Email, Roles: roles}, nil
}

func (c *Client) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	jwksMu.RLock()
	key, ok := jwksKeys[kid]
	fresh := time.Now().Before(jwksTTL)
	jwksMu.RUnlock()

	if ok && fresh {
		return key, nil
	}
	if err := c.fetchJWKS(ctx); err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	jwksMu.RLock()
	key, ok = jwksKeys[kid]
	jwksMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	return key, nil
}

func (c *Client) fetchJWKS(ctx context.Context) error {
	uri := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs",
		strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.Realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}

	jwksMu.Lock()
	defer jwksMu.Unlock()
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		nBytes, _ := base64.RawURLEncoding.DecodeString(k.N)
		eBytes, _ := base64.RawURLEncoding.DecodeString(k.E)
		if len(nBytes) == 0 || len(eBytes) == 0 {
			continue
		}
		jwksKeys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}
	jwksTTL = time.Now().Add(jwksCacheDuration)
	return nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
