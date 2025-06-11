# OIDC GCP Workload Identity Federation (WIF) Helper

A Go package to simplify and secure the use of OIDC tokens for Google Cloud Workload Identity Federation (WIF) and other OIDC providers (e.g., Keycloak). This package provides utilities for token management, validation, and integration with Google Cloud services.

---

## Features
- Flexible WIF configuration via `WIFConfig` struct
- Support for static and dynamic OIDC token sources via the `TokenSupplier` interface
- Token validation and auto-refresh with `ValidatingTokenSource`
- Keycloak OIDC provider integration with caching and expiry handling
- Pub/Sub integration example using federated tokens
- Thread-safe token cache for any OIDC provider

---

## Table of Contents
- [Installation](#installation)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
  - [Google WIF Example](#google-wif-example)
  - [Keycloak OIDC Example](#keycloak-oidc-provider-example)
- [Requirements](#requirements)
- [Specifications](#specifications)
- [Testing](#testing)
- [Running Unit Tests](#running-unit-tests)
- [Things to Note](#things-to-note)
- [Version](#version)
- [Important Notes](#important-notes)
- [License](#license)

---

## Installation

```bash
go get github.com/your-org/2506-pcs-oidc-external-access-go/oidc
```

Or clone this repository and use as a local module.

---

## Directory Structure
- `oidc/google/` : Google WIF helpers, token source, and Pub/Sub example
- `oidc/provider/` : Generic OIDC provider (Keycloak) and token cache
- `tmp/` : Temporary files for test tokens

---

## Usage

### Google WIF Example
```go
cfg := NewWIFConfig(
    "audience",
    "subjectTokenType",
    "tokenURL",
    []string{"scope1", "scope2"},
    "serviceAccountImpersonationURL",
    &StaticTokenSupplier{Token: "your-oidc-token"},
)

baseTS, err := GetGCPTokenSource(context.Background(), cfg)
if err != nil {
    // handle error
}

vts := NewValidatingTokenSource(baseTS, time.Minute) // leeway 1 minute

token, err := vts.Token()
if err != nil {
    // handle error
}

if vts.IsValid() {
    // token is still valid
} else {
    // token expired, will auto-refresh on Token()
}
```

#### Use with Google Pub/Sub
- Set `GCP_PROJECT_ID` and `GCP_PUBSUB_TOPIC` in your environment
- Place a valid federated Google token in `tmp/test_google_token.txt`
- See `.env.example` for required environment variables

### Keycloak OIDC Provider Example
```go
provider := &KeycloakTokenProvider{
    Config: &ConfigKeyCloak{
        KeycloakRealmURL:     "https://keycloak.example.com/realms/your-realm",
        KeycloakClientID:     "client-id",
        KeycloakClientSecret: "client-secret",
        KeycloakClientScopes: []string{"openid"},
    },
    Insecure: false, // set true to skip TLS verification (not recommended for production)
}

cache := NewTokenCache(provider)
token, err := cache.GetValidToken(context.Background())
```

---

## Requirements
- Go 1.18+
- For Google WIF: a valid OIDC token and GCP project with WIF configured
- For Keycloak: a running Keycloak server and a configured OIDC client

---

## Specifications
- Written in idiomatic Go, modular and testable
- Supports Google Cloud Workload Identity Federation (WIF) via OIDC
- Pluggable OIDC provider interface (`TokenProvider`) for extensibility (e.g., Keycloak, Google, custom)
- Thread-safe token caching and auto-refresh with expiry awareness
- Example integration with Google Pub/Sub using federated tokens
- Unit and integration tests provided for all major features
- Environment-based configuration for integration tests (see `.env.example`)
- No external dependencies except standard Go modules and official Google libraries

---

## Testing
- See `oidc/google/wif_test.go`, `oidc/provider/keycloak_test.go`, and `oidc/google/pubsub_wif_test.go` for usage and test cases
- Use `.env.example` to set up required environment variables for integration tests

---

## Running Unit Tests
To run all unit and integration tests:

```bash
go test ./...
```

To run tests for a specific package (e.g., Google helpers):

```bash
go test ./oidc/google
```

For integration tests that require environment variables, copy `.env.example` to `.env` and fill in the required values. Ensure any required tokens are present in the `tmp/` directory as described in the test documentation.

---

## Things to Note
- Ensure your OIDC tokens are securely managed and never committed to version control (see `.gitignore`)
- For Google WIF, make sure your GCP project and service account are properly configured for Workload Identity Federation
- For Keycloak, use production-ready TLS certificates and avoid `Insecure: true` except for local development/testing
- Integration tests require valid environment variables and tokens (see `.env.example` and `tmp/`)
- Always review and update the `CODEOWNERS` and `pull_request_template.md` for team and workflow alignment
- This package is intended for backend/server-side use; do not expose secrets or tokens to the client/browser
- Keep dependencies up to date and review security advisories for Go and Google libraries
- Contributions should include tests and documentation updates as needed

---

## Version
- Initial Release: v0.1.0 (June 2025)
- Status: Beta, API may change before v1.0.0

---

## Important Notes
- This package is designed for backend/server-side use only. Never expose secrets, tokens, or sensitive configuration to the client/browser
- Always use secure storage and transmission for OIDC tokens and credentials
- For production, ensure all endpoints (Keycloak, Google, etc.) use valid TLS certificates
- Review and follow your organization's security and compliance policies when integrating with identity providers
- Contributions are welcome! Please open issues or pull requests for bugs, features, or documentation improvements

---

**Author:**
- [Alfarizi] [Aditya]
- [Tanggal: 2025-06-11]


## License
MIT
