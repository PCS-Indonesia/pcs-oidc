# Keycloak OIDC Token Provider (Go)

Paket ini menyediakan cache token OIDC (id_token) dari Keycloak yang otomatis refresh jika expired, dan reuse jika masih valid. Cocok untuk integrasi ke Google, AWS, atau sistem lain yang membutuhkan OIDC token.

## Cara Penggunaan

### 1. Import Package
Pastikan sudah meng-import package ini di project Anda:
```go
import (
    "context"
    "yourmodule/oidc/provider"
)
```

### 2. Buat Config Keycloak
```go
cfg := &provider.ConfigKeyCloak{
    KeycloakRealmURL:     "https://keycloak.example.com/realms/your-realm",
    KeycloakClientID:     "your-client-id",
    KeycloakClientSecret: "your-client-secret",
    KeycloakClientScopes: []string{"openid"}, // bisa tambah scope lain jika perlu
}
```

### 3. Buat Provider dan Token Cache
```go
keycloakProvider := &provider.KeycloakTokenProvider{
    Config:   cfg,
    Insecure: false, // true jika ingin skip TLS verification (hanya untuk dev/testing)
}
cache := provider.NewTokenCache(keycloakProvider)
```

### 4. Ambil Token Valid (Otomatis Refresh jika Expired)
```go
token, err := cache.GetValidToken(context.Background())
if err != nil {
    // handle error
}
// gunakan token untuk keperluan OIDC
```

### 5. (Opsional) Paksa Expired Token (untuk testing)
```go
cache.ForceExpire(time.Now().Add(-2 * time.Minute))
```

## Catatan
- Token akan otomatis di-refresh jika expired, dan akan direuse jika masih valid.
- Anda bisa menggunakan cache/token ini di goroutine manapun (thread-safe).
- Untuk provider lain (misal Google), cukup implementasikan interface `TokenProvider`.

## Contoh Lengkap
```go
package main

import (
    "context"
    "fmt"
    "yourmodule/oidc/provider"
)

func main() {
    cfg := &provider.ConfigKeyCloak{
        KeycloakRealmURL:     "https://keycloak.example.com/realms/your-realm",
        KeycloakClientID:     "your-client-id",
        KeycloakClientSecret: "your-client-secret",
        KeycloakClientScopes: []string{"openid"},
    }
    keycloakProvider := &provider.KeycloakTokenProvider{Config: cfg, Insecure: false}
    cache := provider.NewTokenCache(keycloakProvider)

    token, err := cache.GetValidToken(context.Background())
    if err != nil {
        panic(err)
    }
    fmt.Println("Token:", token)
}
```

---
