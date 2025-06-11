package oidc_test

import (
	"context"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
)

func TestPublishToPubSubWithExternalWIFToken(t *testing.T) {
	ctx := context.Background()

	// Baca access token Google hasil federasi dari file (hasil test sebelumnya)
	accessToken, err := os.ReadFile("../../tmp/test_google_token.txt")
	require.NoError(t, err)
	require.NotEmpty(t, accessToken)

	// Skip test jika token dummy/error
	if string(accessToken) == "" || len(accessToken) > 12 && string(accessToken[:12]) == "DUMMY_TOKEN" {
		t.Skip("Skipping Pub/Sub test: no valid federated Google token available")
	}

	// Ambil project dan topic dari environment variable agar tidak hardcode
	projectID := "-"
	topicID := "-"
	if projectID == "" || topicID == "" {
		t.Skip("Skipping Pub/Sub test: GCP_PROJECT_ID or GCP_PUBSUB_TOPIC env not set")
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: string(accessToken),
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(10 * time.Minute), // asumsi token masih valid
	})

	client, err := pubsub.NewClient(ctx, projectID, option.WithTokenSource(ts))
	require.NoError(t, err)
	defer client.Close()

	topic := client.Topic(topicID)
	result := topic.Publish(ctx, &pubsub.Message{
		Data: []byte("Hello from WIF external token!"),
	})
	id, err := result.Get(ctx)
	require.NoError(t, err)
	t.Logf("Published message with ID: %s", id)
}
