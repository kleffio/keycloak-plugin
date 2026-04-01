// Package keycloak is the outbound adapter that implements ports.IDPProvider
// by talking to Keycloak over HTTP.
package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kleffio/idp-keycloak/internal/core/domain"
)

// Config holds the Keycloak connection parameters, loaded from env vars.
type Config struct {
	BaseURL       string // internal URL for server-to-server calls, e.g. "http://keycloak:8080"
	PublicBaseURL string // browser-reachable URL returned in OIDC config; falls back to BaseURL
	Realm         string
	ClientID      string
	ClientSecret  string // optional, for confidential clients
	AdminUser     string
	AdminPassword string
	AuthMode      string // "headless" (default) or "redirect"
}

// Client is the production implementation of ports.IDPProvider.
type Client struct {
	cfg  Config
	http *http.Client
}

// New creates a Keycloak client. Call this once at startup.
func New(cfg Config) *Client {
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

func (c *Client) tokenEndpoint() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.Realm)
}

// Login authenticates via the Direct Access Grant (Resource Owner Password Credentials).
func (c *Client) Login(ctx context.Context, username, password string) (*domain.TokenSet, error) {
	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {c.cfg.ClientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid profile email"},
	}
	if c.cfg.ClientSecret != "" {
		data.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint(),
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("keycloak login: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak login: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tok struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		IDToken          string `json:"id_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("keycloak login: parse response: %w", err)
	}
	if tok.Error != "" {
		if tok.Error == "invalid_grant" || strings.Contains(tok.ErrorDescription, "Invalid user credentials") {
			return nil, &domain.ErrUnauthorized{Msg: "invalid username or password"}
		}
		return nil, fmt.Errorf("keycloak login: %s: %s", tok.Error, tok.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak login: unexpected status %d", resp.StatusCode)
	}
	return &domain.TokenSet{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		TokenType:    tok.TokenType,
		ExpiresIn:    tok.ExpiresIn,
		Scope:        tok.Scope,
	}, nil
}

// Register creates a new user in Keycloak via the Admin REST API.
func (c *Client) Register(ctx context.Context, req domain.RegisterRequest) (string, error) {
	adminTok, err := c.adminToken(ctx)
	if err != nil {
		return "", fmt.Errorf("keycloak register: admin token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users",
		strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.Realm)

	payload, err := json.Marshal(map[string]any{
		"username":  req.Username,
		"email":     req.Email,
		"firstName": req.FirstName,
		"lastName":  req.LastName,
		"enabled":   true,
		"credentials": []map[string]any{{
			"type":      "password",
			"value":     req.Password,
			"temporary": false,
		}},
	})
	if err != nil {
		return "", fmt.Errorf("keycloak register: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(string(payload)))
	if err != nil {
		return "", fmt.Errorf("keycloak register: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+adminTok)

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("keycloak register: %w", err)
	}
	defer httpResp.Body.Close()

	switch httpResp.StatusCode {
	case http.StatusCreated:
		loc := httpResp.Header.Get("Location")
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		return parts[len(parts)-1], nil
	case http.StatusConflict:
		return "", &domain.ErrConflict{Msg: "user already exists"}
	default:
		b, _ := io.ReadAll(httpResp.Body)
		return "", fmt.Errorf("keycloak register: status %d: %s", httpResp.StatusCode, string(b))
	}
}

// OIDCConfig returns the OIDC discovery parameters.
// Authority and JwksURI use PublicBaseURL (browser-reachable) if set.
func (c *Client) OIDCConfig() domain.OIDCConfig {
	public := strings.TrimRight(c.cfg.PublicBaseURL, "/")
	if public == "" {
		public = strings.TrimRight(c.cfg.BaseURL, "/")
	}
	authMode := c.cfg.AuthMode
	if authMode == "" {
		authMode = "headless"
	}
	return domain.OIDCConfig{
		Authority: fmt.Sprintf("%s/realms/%s", public, c.cfg.Realm),
		ClientID:  c.cfg.ClientID,
		JwksURI:   fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", public, c.cfg.Realm),
		Realm:     c.cfg.Realm,
		AuthMode:  authMode,
	}
}

// RefreshToken exchanges a refresh token for a new token set via the OAuth2 refresh_token grant.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenSet, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.cfg.ClientID},
		"refresh_token": {refreshToken},
	}
	if c.cfg.ClientSecret != "" {
		data.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenEndpoint(),
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("keycloak refresh: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak refresh: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tok struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		IDToken          string `json:"id_token"`
		TokenType        string `json:"token_type"`
		ExpiresIn        int64  `json:"expires_in"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("keycloak refresh: parse response: %w", err)
	}
	if tok.Error != "" {
		if tok.Error == "invalid_grant" {
			return nil, &domain.ErrUnauthorized{Msg: "refresh token is invalid or expired"}
		}
		return nil, fmt.Errorf("keycloak refresh: %s: %s", tok.Error, tok.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak refresh: unexpected status %d", resp.StatusCode)
	}
	return &domain.TokenSet{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		TokenType:    tok.TokenType,
		ExpiresIn:    tok.ExpiresIn,
		Scope:        tok.Scope,
	}, nil
}

// EnsureRealm creates the configured realm and kleff-panel client in Keycloak
// if they do not already exist. Safe to call on every startup (idempotent).
func (c *Client) EnsureRealm(ctx context.Context) error {
	tok, err := c.adminToken(ctx)
	if err != nil {
		return fmt.Errorf("ensure realm: admin token: %w", err)
	}

	base := strings.TrimRight(c.cfg.BaseURL, "/")

	// Check if realm exists.
	realmURL := fmt.Sprintf("%s/admin/realms/%s", base, c.cfg.Realm)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, realmURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ensure realm: check realm: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Create realm.
		payload, _ := json.Marshal(map[string]any{
			"realm":                 c.cfg.Realm,
			"enabled":               true,
			"registrationAllowed":   true,
			"loginWithEmailAllowed": true,
		})
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost, base+"/admin/realms",
			strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err = c.http.Do(req)
		if err != nil {
			return fmt.Errorf("ensure realm: create realm: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("ensure realm: create realm: status %d", resp.StatusCode)
		}
	}

	// Check if kleff-panel client exists.
	clientsURL := fmt.Sprintf("%s/admin/realms/%s/clients?clientId=%s", base, c.cfg.Realm, c.cfg.ClientID)
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, clientsURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err = c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ensure realm: check client: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var clients []map[string]any
	if err := json.Unmarshal(body, &clients); err != nil || len(clients) == 0 {
		// Create client.
		payload, _ := json.Marshal(map[string]any{
			"clientId":                  c.cfg.ClientID,
			"enabled":                   true,
			"publicClient":              true,
			"directAccessGrantsEnabled": true,
			"standardFlowEnabled":       false,
		})
		req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
			fmt.Sprintf("%s/admin/realms/%s/clients", base, c.cfg.Realm),
			strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err = c.http.Do(req)
		if err != nil {
			return fmt.Errorf("ensure realm: create client: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("ensure realm: create client: status %d", resp.StatusCode)
		}
	}

	return nil
}

func (c *Client) adminToken(ctx context.Context) (string, error) {
	endpoint := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"))

	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {c.cfg.AdminUser},
		"password":   {c.cfg.AdminPassword},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Error != "" {
		return "", fmt.Errorf("keycloak admin token: %s", tok.Error)
	}
	return tok.AccessToken, nil
}
