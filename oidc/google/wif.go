package oidc

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
)

// TokenSupplier abstracts the OIDC token supplier for GCP WIF.
// Implement this interface for static or dynamic OIDC token sources.
type TokenSupplier interface {
	SubjectToken(ctx context.Context, opts externalaccount.SupplierOptions) (string, error)
}

// StaticTokenSupplier implements TokenSupplier for a static OIDC token string.
type StaticTokenSupplier struct {
	Token string
}

// SubjectToken returns the static OIDC token.
func (s *StaticTokenSupplier) SubjectToken(ctx context.Context, opts externalaccount.SupplierOptions) (string, error) {
	return s.Token, nil
}

// WIFConfig holds configuration for GCP Workload Identity Federation.
// TokenSupplier is any implementation that returns a valid OIDC token (id_token).
type WIFConfig struct {
	Audience                       string
	SubjectTokenType               string
	TokenURL                       string
	Scopes                         []string
	ServiceAccountImpersonationURL string
	TokenSupplier                  TokenSupplier
}

// NewWIFConfig is a constructor for WIFConfig with all parameters required (no hardcoded defaults).
func NewWIFConfig(audience, subjectTokenType, tokenURL string, scopes []string, saImpersonationURL string, tokenSupplier TokenSupplier) WIFConfig {
	return WIFConfig{
		Audience:                       audience,
		SubjectTokenType:               subjectTokenType,
		TokenURL:                       tokenURL,
		Scopes:                         scopes,
		ServiceAccountImpersonationURL: saImpersonationURL,
		TokenSupplier:                  tokenSupplier,
	}
}

// GetGCPTokenSource returns an oauth2.TokenSource for GCP using Workload Identity Federation.
// This function is flexible: you can supply any TokenSupplier (static or dynamic).
// Best practice: validate config, wrap with ReuseTokenSourceWithExpiry, and allow leeway config.
func GetGCPTokenSource(ctx context.Context, cfg WIFConfig, leeway ...time.Duration) (oauth2.TokenSource, error) {
	// Validate required fields
	if cfg.Audience == "" || cfg.SubjectTokenType == "" || cfg.TokenURL == "" || cfg.TokenSupplier == nil {
		return nil, fmt.Errorf("missing required WIFConfig fields")
	}

	wifConfig := externalaccount.Config{
		Audience:                       cfg.Audience,
		SubjectTokenType:               cfg.SubjectTokenType,
		TokenURL:                       cfg.TokenURL,
		Scopes:                         cfg.Scopes,
		ServiceAccountImpersonationURL: cfg.ServiceAccountImpersonationURL,
		SubjectTokenSupplier:           cfg.TokenSupplier,
	}

	ts, err := externalaccount.NewTokenSource(ctx, wifConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP WIF token source: %w", err)
	}

	return ts, nil
}

// ValidatingTokenSource wraps an oauth2.TokenSource to allow explicit validity and expiry checks.
type ValidatingTokenSource struct {
	Source      oauth2.TokenSource
	leeway      time.Duration
	cachedToken *oauth2.Token
}

// NewValidatingTokenSource returns a TokenSource that caches and validates expiry with leeway.
func NewValidatingTokenSource(src oauth2.TokenSource, leeway time.Duration) *ValidatingTokenSource {
	return &ValidatingTokenSource{Source: src, leeway: leeway}
}

// Token returns a valid token, refreshing if expired or invalid.
func (v *ValidatingTokenSource) Token() (*oauth2.Token, error) {
	if v.cachedToken != nil && v.IsValid() {
		return v.cachedToken, nil
	}
	tok, err := v.Source.Token()
	if err != nil {
		return nil, err
	}
	v.cachedToken = tok
	return tok, nil
}

// IsValid checks if the cached token is valid and not expired (with leeway).
func (v *ValidatingTokenSource) IsValid() bool {
	if v.cachedToken == nil {
		return false
	}
	if !v.cachedToken.Valid() {
		return false
	}
	if v.leeway > 0 && !v.cachedToken.Expiry.IsZero() {
		return time.Now().Add(v.leeway).Before(v.cachedToken.Expiry)
	}
	return true
}

// Note:
// Each call to generate a WIF (Workload Identity Federation) token via STS will produce a new, independent Google access token.
// Multiple tokens generated in this way are all valid and can be used in parallel (e.g., for Pub/Sub clients) until they expire.
// Tokens do not invalidate each other. Ensure your OIDC token is still valid (not expired or stale) when generating WIF tokens.
