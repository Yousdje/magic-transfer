# MagicTransfer Security Model

## Zero-Knowledge Architecture

MagicTransfer uses a **zero-knowledge** design inspired by Firefox Send. The server never sees your data.

### What the server stores
- A random file ID (opaque token)
- An encrypted blob (binary — server cannot read it)
- Encrypted metadata (filename, size — encrypted separately, server cannot read it)
- An auth token (HKDF-derived, proves download authorization without revealing the key)
- Expiry timestamp

### What the server never sees
- The encryption key (IKM) — lives only in the URL fragment and the browser
- Plaintext file contents
- Filenames or file types
- Text content

## How It Works

### Encryption (browser-side)
1. Browser generates a 256-bit random secret (IKM) using `crypto.getRandomValues()`
2. HKDF-SHA-256 derives three domain-separated keys from the IKM:
   - **fileKey** (AES-256-GCM) — encrypts file data in 64KB chunks
   - **metaKey** (AES-256-GCM) — encrypts filename, size, MIME type
   - **authKey** — hex-encoded, sent to server as a bearer token
3. File data is encrypted chunk-by-chunk with deterministic IVs (base nonce XOR sequence number)
4. Encrypted blob + encrypted metadata + auth token are uploaded to the server
5. The IKM is placed in the URL fragment: `https://domain/d/{id}#base64url(ikm)`

### Key Sharing
The URL fragment (everything after `#`) is **never sent to the server** per HTTP specifications (RFC 3986). It is only processed by the browser's JavaScript. The fragment is stripped from the URL bar immediately after extraction via `history.replaceState()`.

### Download (browser-side)
1. Recipient opens the share URL
2. Browser reads the IKM from the URL fragment
3. Fragment is immediately stripped from the URL bar
4. Keys are re-derived via HKDF
5. Auth token is sent to server to authorize the download
6. Encrypted blob is downloaded and decrypted entirely in the browser
7. Transfer is marked complete (burn-after-read)

### Burn After Read
All transfers are single-use. After the recipient downloads and decrypts, the encrypted blob is permanently deleted from the server.

## Threat Model

### Protected against
- **Server compromise**: Even if the server is hacked, attackers only get encrypted blobs they cannot decrypt
- **Network eavesdropping**: TLS protects the transport; encryption protects the content
- **Server operator**: The operator cannot read any transferred data
- **Brute force**: The 256-bit IKM has 2^256 possible values — computationally infeasible to guess

### Not protected against
- **Compromised browser**: If an attacker controls the recipient's browser, they can read decrypted data
- **Malicious JavaScript**: If the server serves modified JS, it could exfiltrate keys (mitigated by CSP headers)
- **Link interception**: Anyone who obtains the full share URL (including fragment) can decrypt the data
- **Metadata leakage**: The server knows IP addresses, transfer timing, and encrypted blob sizes

### Mitigations
- **Content-Security-Policy** with nonces prevents XSS and script injection
- **Security headers**: X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy no-referrer
- **Rate limiting**: Per-IP limits on uploads and downloads
- **Session expiry**: Transfers auto-expire after 1 hour
- **Non-root container**: Docker runs as unprivileged user with dropped capabilities

## Cryptographic Primitives
- **Key derivation**: HKDF-SHA-256 (Web Crypto API)
- **Encryption**: AES-256-GCM (Web Crypto API)
- **IV construction**: Deterministic — base nonce XOR sequence number (unique per chunk)
- **Auth**: HMAC-based token comparison via `hmac.compare_digest` (timing-safe)
