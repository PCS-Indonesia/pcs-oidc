package oidc

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ConfigKeyCloak holds configuration for Keycloak OIDC provider.
// This struct is used to configure the KeycloakTokenProvider
// It contains the Keycloak realm URL, client ID, client secret, and optional scopes.
// The KeycloakRealmURL is the base URL of the Keycloak server, including the realm path.
// The KeycloakClientID is the client ID registered in Keycloak.
// The KeycloakClientSecret is the secret associated with the client ID.
// The KeycloakClientScopes is a list of OIDC scopes to request. If empty, defaults to ["openid"].
type ConfigKeyCloak struct {
	KeycloakRealmURL     string
	KeycloakClientID     string
	KeycloakClientSecret string
	KeycloakClientScopes []string // OIDC scopes, default to ["openid"] if empty
}

// TokenCache is a generic cache for any TokenProvider
// It will always return a valid token, refreshing if needed
// It uses a mutex to ensure thread-safe access to the token
// It holds the provider, current token, and expiry time
// The cache will automatically refresh the token if it is expired or about to expire
type TokenCache struct {
	provider TokenProvider
	token    string
	expiry   time.Time
	mu       sync.Mutex
}

// KeycloakTokenProvider implements TokenProvider for Keycloak
// Holds config and TLS option only
// Tidak menyimpan token di struct ini

type KeycloakTokenProvider struct {
	Config   *ConfigKeyCloak
	Insecure bool
}

// TokenProvider is a generic interface for OIDC token providers
// (bisa diimplementasikan Keycloak, Google, dsb)
type TokenProvider interface {
	FetchToken(ctx context.Context) (string, error)
}

// FetchToken fetches a new id_token from Keycloak
func (k *KeycloakTokenProvider) FetchToken(ctx context.Context) (string, error) {
	// Check if Keycloak configuration is complete
	// Ensure that KeycloakRealmURL, KeycloakClientID, and KeycloakClientSecret are provided
	if k.Config.KeycloakRealmURL == "" || k.Config.KeycloakClientID == "" || k.Config.KeycloakClientSecret == "" {
		return "", errors.New("Keycloak configuration is incomplete: KeycloakRealmURL, KeycloakClientID, and KeycloakClientSecret must be provided")
	}
	// Build Keycloak token endpoint URL
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", k.Config.KeycloakRealmURL)
	var httpClient *http.Client
	if k.Insecure {
		// If insecure, create a custom HTTP client that skips TLS verification
		// This is not recommended for production use, but useful for testing or self-signed certs
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		// Use custom transport with insecure TLS config
		// This allows the client to connect to Keycloak without verifying the server's TLS certificate
		// This is useful for development or testing environments with self-signed certificates
		// or when the Keycloak server uses a certificate that is not trusted by the system's CA store
		// Note: This should not be used in production as it exposes the client
		httpClient = &http.Client{Transport: tr}
	} else {
		// Use the default HTTP client with system CA verification
		// This is the recommended approach for production use
		// It ensures that the client verifies the server's TLS certificate against trusted CAs
		// This prevents
		httpClient = http.DefaultClient
	}
	// If scopes are not provided, default to "openid"
	scopes := k.Config.KeycloakClientScopes
	if scopes == nil || len(scopes) == 0 || (len(scopes) > 0 && scopes[0] == "") {
		scopes = []string{"openid"}
	}
	// Create OAuth2 client credentials config
	conf := &clientcredentials.Config{
		ClientID:     k.Config.KeycloakClientID,
		ClientSecret: k.Config.KeycloakClientSecret,
		TokenURL:     tokenURL,
		Scopes:       scopes,
	}
	// Set the HTTP client to use the custom or default client
	// This allows the OAuth2 library to use the configured HTTP client
	// for making requests to the Keycloak token endpoint
	// This is important for handling TLS verification and other HTTP settings
	// It ensures that the token request uses the correct HTTP client configuration
	// This is necessary to ensure that the OAuth2 library uses the correct HTTP client
	// for making requests to the Keycloak token endpoint
	// This is important for handling TLS verification and other HTTP settings
	// This allows the OAuth2 library to use the configured HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	// Create an OAuth2 token source using the client credentials config
	token, err := conf.Token(ctx)
	if err != nil {
		// If there is an error fetching the token, return an error
		// This could be due to invalid credentials, network issues, etc.
		// The error is wrapped with additional context for better debugging
		// This provides more context about the error, making it easier to debug
		// the issue if it occurs
		return "", fmt.Errorf("failed to get token from Keycloak: %w", err)
	}

	// Extract the id_token from the OAuth2 token response
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		// Check if id_token is present and valid
		// If id_token is not present or empty, return an error
		// This indicates that the Keycloak token response did not include an id_token
		return "", errors.New("failed to extract id_token from Keycloak token response")
	}

	// Return the id_token as a string
	// This is the final token that can be used for authentication
	// It can be used to authenticate requests to protected resources
	// The id_token is a JSON Web Token (JWT) that contains user identity information
	// The id_token is signed by Keycloak and can be verified by the client
	return idToken, nil
}

// NewTokenCache creates a new cache for a given provider
// This cache will always return a valid token, refreshing it if needed
func NewTokenCache(provider TokenProvider) *TokenCache {
	return &TokenCache{provider: provider}
}

// getJWTExpiry extracts the exp (expiry) field from a JWT token payload
// Returns the expiry as Unix timestamp (seconds since epoch)
// Returns an error if the token is invalid or does not contain exp
func getJWTExpiry(token string) (int64, error) {
	// JWT tokens are in the format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		// If the token does not have at least 2 parts, it is invalid
		// JWT tokens must have at least 2 parts: header and payload
		// The header contains metadata about the token, such as the algorithm used to sign it
		// The payload contains the claims, such as the user identity and expiration time
		// The signature is used to verify the integrity of the token
		return 0, errors.New("invalid token format")
	}

	// Decode the payload part of the JWT token
	// The payload contains the claims, including the expiration time (exp)
	// The payload is base64 URL encoded, so we use RawURLEncoding to decode it
	// The payload is the second part of the JWT token (index 1)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// If there is an error decoding the payload, return an error
		// This could be due to an invalid base64 encoding or an empty payload
		// The payload must be a valid base64 URL encoded string
		return 0, err
	}

	// Unmarshal the JSON payload into a map to extract the exp field
	// The exp field is a Unix timestamp indicating when the token expires
	// The exp field is a standard claim in JWT tokens that indicates the expiration time
	// The exp field is a numeric value representing the expiration time in seconds since epoch
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		// If there is an error unmarshalling the JSON payload, return an error
		// This could be due to an invalid JSON format or an empty payload
		// The payload must be a valid JSON object with the exp field present
		return 0, err
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, errors.New("exp not found in token")
	}
	return int64(exp), nil
}

// GetValidToken returns a valid token from cache, or fetches a new one if expired or invalid
// Thread-safe: uses mutex to protect concurrent access
func (c *TokenCache) GetValidToken(ctx context.Context) (string, error) {
	// Lock the cache to ensure thread-safe access
	// This prevents multiple goroutines from accessing the cache simultaneously
	c.mu.Lock()
	defer c.mu.Unlock() // Ensure the lock is released after this function returns
	// If token exists and not expired (with 1 minute buffer), reuse it
	if c.token != "" && time.Now().Before(c.expiry.Add(-1*time.Minute)) {
		// If the token is still valid, return it
		// This means the token is still valid and can be reused
		// The expiry is checked with a 1 minute buffer to ensure the token is not close to expiring
		return c.token, nil
	}
	// Otherwise, fetch new token from provider
	token, err := c.provider.FetchToken(ctx)
	if err != nil {
		// If there is an error fetching the token, return an error
		// This could be due to network issues, invalid credentials, etc.
		return "", err
	}

	// If token is successfully fetched, parse the expiry from the JWT
	// The expiry is extracted from the token payload using the getJWTExpiry function
	// This function decodes the JWT token and extracts the exp field
	exp, err := getJWTExpiry(token)
	if err != nil {
		return "", err
	}

	c.token = token
	c.expiry = time.Unix(exp, 0)
	return c.token, nil
}

// ForceExpire sets the expiry to a specific time (for testing purposes)
// This allows unit tests to simulate expired tokens
func (c *TokenCache) ForceExpire(t time.Time) {
	// Lock the cache to ensure thread-safe access
	// This is useful for testing scenarios where we want to force the cache to refresh
	c.mu.Lock()
	defer c.mu.Unlock()
	// Set the token to empty and expiry to the specified time
	c.expiry = t
}
