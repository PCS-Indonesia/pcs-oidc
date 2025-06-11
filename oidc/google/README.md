# GCP Workload Identity Federation (WIF) OIDC TokenSource Helper

Paket ini menyediakan utilitas untuk mengelola OIDC token source pada skenario Google Cloud Workload Identity Federation (WIF), dengan fitur validasi dan refresh otomatis token.

## Fitur
- Mendukung konfigurasi WIF secara fleksibel melalui struct `WIFConfig`.
- Mendukung sumber token OIDC statis maupun dinamis melalui interface `TokenSupplier`.
- Wrapper `ValidatingTokenSource` untuk pengecekan validitas dan expiry token, serta refresh otomatis jika token sudah tidak valid.

## Cara Pakai

### 1. Inisialisasi WIFConfig
```go
cfg := NewWIFConfig(
    "audience",
    "subjectTokenType",
    "tokenURL",
    []string{"scope1", "scope2"},
    "serviceAccountImpersonationURL",
    &StaticTokenSupplier{Token: "your-oidc-token"},
)
```

### 2. Buat TokenSource dasar
```go
baseTS, err := GetGCPTokenSource(context.Background(), cfg)
if err != nil {
    // handle error
}
```

### 3. Bungkus dengan ValidatingTokenSource
```go
vts := NewValidatingTokenSource(baseTS, time.Minute) // leeway 1 menit
```

### 4. Ambil token yang valid
```go
token, err := vts.Token()
if err != nil {
    // handle error
}
```

### 5. (Opsional) Cek validitas token secara manual
```go
if vts.IsValid() {
    // token masih valid
} else {
    // token expired, akan di-refresh otomatis saat panggil Token()
}
```

## Testing
Lihat file `wif_test.go` untuk contoh penggunaan dan pengujian.

## Notes
- Each call to generate a WIF (Workload Identity Federation) token via STS will produce a new, independent Google access token.
- Multiple tokens generated in this way are intended to be valid in parallel, but **all depend on the OIDC token (subject token) still being valid and not stale** at the time of each WIF token generation.
- If the OIDC token becomes expired or stale, subsequent WIF token generations will fail with an error (e.g., `invalid_grant`, `ID Token ... is stale to sign-in`).
- Tokens do not invalidate each other, but all WIF tokens are only as valid as the OIDC token used to generate them.
- For reliable parallel usage, always use a fresh OIDC token for each WIF token generation if possible.

## Lisensi
MIT
