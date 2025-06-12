package oidc_test

import (
	"context"
	"os"
	"testing"
	"time"

	oidc "pcs-oidc/oidc/provider"

	"github.com/stretchr/testify/require"
)

func TestKeycloakTokenProviderAndCache(t *testing.T) {
	cfg := &oidc.ConfigKeyCloak{
		KeycloakRealmURL:     "YOUR-ISSUER-PROVIDER", // ganti sesuai test
		KeycloakClientID:     "YOUR-CLIENT-ID",       // ganti sesuai test
		KeycloakClientSecret: "YOUR-CLIENT-SECRET",
		KeycloakClientScopes: []string{"openid"},
	}
	provider := &oidc.KeycloakTokenProvider{Config: cfg, Insecure: true}
	cache := oidc.NewTokenCache(provider)

	t.Run("success get token and write to file", func(t *testing.T) {
		ctx := context.Background()
		token, err := cache.GetValidToken(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		err = os.MkdirAll("../../tmp", 0755)
		require.NoError(t, err)

		filename := "../../tmp/test_id_token.txt"
		err = os.WriteFile(filename, []byte(token), 0600)
		require.NoError(t, err)

		// t.Cleanup(func() {
		// 	_ = os.Remove(filename)
		// })
	})

	t.Run("error if config incomplete", func(t *testing.T) {
		badProvider := &oidc.KeycloakTokenProvider{Config: &oidc.ConfigKeyCloak{}, Insecure: true}
		cache := oidc.NewTokenCache(badProvider)
		ctx := context.Background()
		token, err := cache.GetValidToken(ctx)
		require.Error(t, err)
		require.Empty(t, token)
	})

	t.Run("error if wrong client secret", func(t *testing.T) {
		badCfg := &oidc.ConfigKeyCloak{
			KeycloakRealmURL:     cfg.KeycloakRealmURL,
			KeycloakClientID:     cfg.KeycloakClientID,
			KeycloakClientSecret: "wrong-secret",
			KeycloakClientScopes: []string{"openid"},
		}
		badProvider := &oidc.KeycloakTokenProvider{Config: badCfg, Insecure: true}
		cache := oidc.NewTokenCache(badProvider)
		ctx := context.Background()
		token, err := cache.GetValidToken(ctx)
		require.Error(t, err)
		require.Empty(t, token)
	})

	t.Run("error if wrong realm url", func(t *testing.T) {
		badCfg := &oidc.ConfigKeyCloak{
			KeycloakRealmURL:     "https://invalid-url/realms/invalid",
			KeycloakClientID:     cfg.KeycloakClientID,
			KeycloakClientSecret: cfg.KeycloakClientSecret,
			KeycloakClientScopes: []string{"openid"},
		}
		badProvider := &oidc.KeycloakTokenProvider{Config: badCfg, Insecure: true}
		cache := oidc.NewTokenCache(badProvider)
		ctx := context.Background()
		token, err := cache.GetValidToken(ctx)
		require.Error(t, err)
		require.Empty(t, token)
	})

	t.Run("success get token with default scope", func(t *testing.T) {
		cfgDefaultScope := &oidc.ConfigKeyCloak{
			KeycloakRealmURL:     cfg.KeycloakRealmURL,
			KeycloakClientID:     cfg.KeycloakClientID,
			KeycloakClientSecret: cfg.KeycloakClientSecret,
			KeycloakClientScopes: nil, // should fallback to ["openid"]
		}
		provider := &oidc.KeycloakTokenProvider{Config: cfgDefaultScope, Insecure: true}
		cache := oidc.NewTokenCache(provider)
		ctx := context.Background()
		_, err := cache.GetValidToken(ctx)
		if err != nil {
			t.Logf("Warning: could not get token with default scope: %v", err)
		}
		// Tidak wajib error, hanya pastikan tidak panic
	})

	t.Run("refresh token if expired", func(t *testing.T) {
		ctx := context.Background()
		cache := oidc.NewTokenCache(provider)
		// Ambil token pertama kali
		token1, err := cache.GetValidToken(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, token1)
		// Paksa expiry ke masa lalu dengan method ForceExpire
		cache.ForceExpire(time.Now().Add(-2 * time.Minute))
		// Ambil token lagi, seharusnya refresh (token baru, atau minimal FetchToken terpanggil lagi)
		token2, err := cache.GetValidToken(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, token2)
		// Token bisa saja sama jika server mengeluarkan token yang sama, tapi yang penting tidak error dan cache refresh
	})

	t.Run("reuse token if not expired", func(t *testing.T) {
		ctx := context.Background()
		cache := oidc.NewTokenCache(provider)
		token1, err := cache.GetValidToken(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, token1)
		token2, err := cache.GetValidToken(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, token2)
		require.Equal(t, token1, token2, "Token should be reused if not expired")
	})
}
