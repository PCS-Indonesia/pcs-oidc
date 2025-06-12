package oidc_test

import (
	"context"
	"errors"
	"os"
	"testing"

	gcpwif "module github.com/PCS-Indonesia/pcs-oidc/oidc/google"

	"cloud.google.com/go/pubsub"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
	"google.golang.org/api/option"
)

type dummyTokenSupplier struct {
	token string
	err   error
}

// Perbaiki signature agar cocok dengan interface TokenSupplier dari gcpwif
func (d *dummyTokenSupplier) SubjectToken(ctx context.Context, opts externalaccount.SupplierOptions) (string, error) {
	return d.token, d.err
}

func TestGetGCPTokenSource(t *testing.T) {
	ctx := context.Background()
	validToken := "YOUR_TOKEN_ACCESS" // JWT with exp in the far future
	t.Run("success with valid static token", func(t *testing.T) {
		supplier := &gcpwif.StaticTokenSupplier{Token: validToken}
		cfg := gcpwif.NewWIFConfig(
			"YOUR_AUDIENCE",            // Change to your audience
			"YOUR_SUBJECT_TOKEN_TYPE",  // Change to your subject token type
			"YOUR_TOKEN_URL",           // Change to your token URL
			[]string{"YOUR_SCOPES"},    // Change to your scopes
			"YOUR_SERVICE_ACCOUNT_URL", // Change to your service account URL
			supplier,
		)
		ts, err := gcpwif.GetGCPTokenSource(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, ts)

		// Simpan OIDC token ke file
		err = writeToFile("../../tmp/test_oidc_token.txt", validToken)
		require.NoError(t, err)

		// Ambil token Google (GCP access token) dan simpan ke file
		googleToken, err := ts.Token()
		if err == nil {
			err = writeToFile("../../tmp/test_google_token.txt", googleToken.AccessToken)
			require.NoError(t, err)
		} else {
			// Tetap buat file dummy agar file selalu ada untuk pengecekan manual
			_ = writeToFile("../../tmp/test_google_token.txt", "DUMMY_TOKEN_ERROR: "+err.Error())
			t.Logf("Gagal ambil Google token: %v", err)
		}
	})

	t.Run("error if token supplier returns error", func(t *testing.T) {
		supplier := &dummyTokenSupplier{err: errors.New("token error")}
		cfg := gcpwif.NewWIFConfig(
			"YOUR_AUDIENCE",            // Change to your audience
			"YOUR_SUBJECT_TOKEN_TYPE",  // Change to your subject token type
			"YOUR_TOKEN_URL",           // Change to your token URL
			[]string{"YOUR_SCOPES"},    // Change to your scopes
			"YOUR_SERVICE_ACCOUNT_URL", // Change to your service account URL
			supplier,
		)
		ts, err := gcpwif.GetGCPTokenSource(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, ts)
		_, err = ts.Token()
		require.Error(t, err)
	})

	t.Run("error if config missing required fields", func(t *testing.T) {
		supplier := &gcpwif.StaticTokenSupplier{Token: validToken}
		cfg := gcpwif.WIFConfig{
			Audience:         "",
			SubjectTokenType: "",
			TokenURL:         "",
			Scopes:           nil,
			TokenSupplier:    supplier,
		}
		ts, err := gcpwif.GetGCPTokenSource(ctx, cfg)
		require.Error(t, err)
		require.Nil(t, ts)
	})
}

func TestMultipleWIFTokensAreValidForPubSub(t *testing.T) {
	ctx := context.Background()
	validToken := "YOUR_TOKEN_ACCESS" // JWT with exp in the far future, ganti dengan token valid

	supplier := &gcpwif.StaticTokenSupplier{Token: validToken}
	cfg := gcpwif.NewWIFConfig(
		"YOUR_AUDIENCE",            // Change to your audience
		"YOUR_SUBJECT_TOKEN_TYPE",  // Change to your subject token type
		"YOUR_TOKEN_URL",           // Change to your token URL
		[]string{"YOUR_SCOPES"},    // Change to your scopes
		"YOUR_SERVICE_ACCOUNT_URL", // Change to your service account URL
		supplier,
	)

	ts1, err := gcpwif.GetGCPTokenSource(ctx, cfg)
	require.NoError(t, err)
	token1, err := ts1.Token()
	require.NoError(t, err)
	require.NotEmpty(t, token1.AccessToken)

	ts2, err := gcpwif.GetGCPTokenSource(ctx, cfg)
	require.NoError(t, err)
	token2, err := ts2.Token()
	require.NoError(t, err)
	require.NotEmpty(t, token2.AccessToken)

	// Kedua token harus berbeda (karena setiap call STS menghasilkan token baru), tapi keduanya valid
	require.NotEqual(t, token1.AccessToken, token2.AccessToken)

	// Coba gunakan kedua token untuk membuat client Pub/Sub
	projectID := "YOUR_PROJECT_ID" // Ganti dengan project ID Anda
	topicID := "YOUR_TOPIC_ID"     // Ganti dengan topic ID Anda
	if projectID == "" || topicID == "" {
		t.Skip("Skipping Pub/Sub test: GCP_PROJECT_ID or GCP_PUBSUB_TOPIC env not set")
	}

	tsPub1 := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token1.AccessToken,
		TokenType:   "Bearer",
		Expiry:      token1.Expiry,
	})
	client1, err := pubsub.NewClient(ctx, projectID, option.WithTokenSource(tsPub1))
	require.NoError(t, err)
	defer client1.Close()
	topic1 := client1.Topic(topicID)
	result1 := topic1.Publish(ctx, &pubsub.Message{Data: []byte("Test with token1")})
	_, err = result1.Get(ctx)
	require.NoError(t, err)

	tsPub2 := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token2.AccessToken,
		TokenType:   "Bearer",
		Expiry:      token2.Expiry,
	})
	client2, err := pubsub.NewClient(ctx, projectID, option.WithTokenSource(tsPub2))
	require.NoError(t, err)
	defer client2.Close()
	topic2 := client2.Topic(topicID)
	result2 := topic2.Publish(ctx, &pubsub.Message{Data: []byte("Test with token2")})
	_, err = result2.Get(ctx)
	require.NoError(t, err)
}

// Tambahkan fungsi utilitas untuk menulis ke file
func writeToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0600)
}
