# Ryus Vault
### Security Project · Python · Flask · Zero-Knowledge Authentication

![Python](https://img.shields.io/badge/python-3.12-3776AB?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=flat-square&logo=flask)
![Crypto](https://img.shields.io/badge/crypto-secp256k1%20%7C%20AES--256--GCM-blueviolet?style=flat-square)
![ZKP](https://img.shields.io/badge/auth-Fiat--Shamir%20Schnorr%20ZKP-orange?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

> A self-hosted password vault with zero-knowledge authentication. The server stores an elliptic curve public key — never a password or its hash. Vault contents are encrypted client-side; the server holds only ciphertext it cannot read.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
   - [Directory Structure](#directory-structure)
   - [Layer Breakdown](#layer-breakdown)
3. [Cryptography](#cryptography)
   - [Authentication — OR-Schnorr / Fiat-Shamir](#authentication--or-schnorr--fiat-shamir)
   - [Vault Encryption — AES-256-GCM + HKDF](#vault-encryption--aes-256-gcm--hkdf)
   - [Master Secret Protection](#master-secret-protection)
4. [API](#api)
5. [Security](#security)
6. [Technology Stack](#technology-stack)
7. [Running](#running)
8. [Configuration](#configuration)

---

## Overview

Ryus Vault is a self-hosted password manager where authentication never transmits a password — not in plaintext, not as a hash. Login is based on an **OR-Schnorr zero-knowledge proof** made non-interactive via the **Fiat-Shamir heuristic**, operating on the **secp256k1** elliptic curve. Vault entries are encrypted in the browser before being sent; the backend stores and serves opaque ciphertext.

**Key properties:**
- Zero-knowledge authentication — server verifies a mathematical proof, not a credential
- Client-side vault encryption — AES-256-GCM, Web Crypto API, no plaintext reaches the server
- Encrypted secret storage — server holds an AES-GCM encrypted copy of the derived secret for migration purposes only; login does not require it
- Clean Architecture — domain layer has no dependency on Flask, SQLite, or `py-ecc`

---

## Architecture

### Directory Structure

```
src/
├── crypto/
│   ├── domain/          # SchnorrProtocol, VaultCipher (abstract interfaces)
│   └── implementation/  # SchnorrProtocolImpl (py-ecc/secp256k1)
│                        # VaultCipherImpl (AES-256-GCM + HKDF)
├── backend/
│   ├── domain/          # User, VaultEntry entities; repository interfaces
│   └── implementation/  # AuthRepositoryImpl, VaultRepositoryImpl (SQLite)
├── api/
│   ├── routes/          # Blueprints: /api/auth, /api/vault
│   ├── middleware/       # JWT auth, rate limiting, CSP headers
│   ├── schemas/         # Pydantic input validation
│   └── errors/          # error handlers
├── config/              # Settings (env variables)
├── logs/                # sanitized logger
└── web/
    ├── templates/        # Jinja2 templates (login, register, vault)
    └── static/js/
        ├── crypto.js     # secp256k1 point arithmetic (BigInt) + Web Crypto API
        ├── login.js      # OR-proof generation in the browser
        ├── register.js   # key derivation, registration flow
        └── vault.js      # client-side encrypt / decrypt
```

### Layer Breakdown

| Layer | Location | Responsibility |
|---|---|---|
| **Domain** | `crypto/domain`, `backend/domain` | Abstract interfaces, entities (`User`, `VaultEntry`), no framework dependencies |
| **Implementation** | `crypto/implementation`, `backend/implementation` | `py-ecc` Schnorr, `cryptography` AES/HKDF, SQLite repositories |
| **API** | `api/` | Flask blueprints, Pydantic schemas, JWT middleware, rate limiting |
| **Client** | `web/static/js/` | secp256k1 arithmetic, proof generation, AES-GCM via Web Crypto API |

Dependencies flow inward — `domain` modules have no knowledge of Flask, SQLite, or any crypto library.

---

## Cryptography

### Authentication — OR-Schnorr / Fiat-Shamir

Login uses a non-interactive **OR-Schnorr identification protocol** transformed via the Fiat-Shamir heuristic. The client proves knowledge of `secret` (PBKDF2 derivative of the password) without transmitting it.

**Registration:**

1. Client derives `secret` from the password via PBKDF2-HMAC-SHA256 (200 000 iterations, 32-byte salt).
2. Computes `public_key = secret × G` on secp256k1.
3. Sends `(username, public_key, salt)` to the server. `secret` never leaves the browser.
4. Server generates a random dummy key pair `(dummy_secret, dummy_pk)`, stores `dummy_pk`, discards `dummy_secret`.

**Login:**

```
Simulated branch (branch1):
  c1, s1 ← random
  R1 = s1·G + c1·dummy_pk            # back-computed commitment

Real branch (branch0):
  r  ← random nonce
  R0 = r·G

Fiat-Shamir challenge:
  c_total = SHA-256(R0 ‖ R1 ‖ real_pk ‖ dummy_pk ‖ username)
  c0 = c_total − c1  (mod ORDER)
  s0 = r − c0·secret (mod ORDER)

Proof sent: (R0, c0, s0, R1, c1, s1)
```

**Server verification:**

```
c0 + c1 ≡ c_total         (mod ORDER)
s0·G + c0·real_pk  == R0
s1·G + c1·dummy_pk == R1
```

The OR construction (Cramer–Damgård–Schoenmakers) makes both branches computationally indistinguishable. The constraint `c0 + c1 = c_total` prevents forging a valid proof without knowing at least one secret: an attacker would need to fix `c0` before `c_total` is known, which the deterministic Fiat-Shamir hash makes impossible.

Curve: **secp256k1**, GROUP ORDER ≈ 2²⁵⁶.

### Vault Encryption — AES-256-GCM + HKDF

```
secret + per-user salt
        │
        └── HKDF-SHA256 (info: "ryus-vault-key")
                  │
                  └── 256-bit AES-GCM key
                            │
                            ├── encrypt(entry plaintext) → (ciphertext, nonce)
                            └── decrypt(ciphertext, nonce) → plaintext
```

Encryption and decryption run entirely in the browser via the **Web Crypto API**. `crypto.js` implements secp256k1 point arithmetic from scratch using `BigInt` — no external cryptographic library on the client side.

### Master Secret Protection

The server stores `encrypted_secret` per user — the PBKDF2-derived `secret` encrypted with AES-256-GCM under `VAULT_MASTER_SECRET`. This value is not used for login verification; it exists solely for potential data migration. It is reversibly encrypted, not hashed.

---

## API

### Auth — `/api/auth`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/init/<username>` | Returns `salt` and `dummy_pk`. Returns random valid-shaped data for non-existent users (enumeration protection). |
| `POST` | `/register` | Body: `username`, `secret`, `public_key_x`, `public_key_y`, `salt`. |
| `POST` | `/login` | Body: `username`, `branch0 {commitment_x, commitment_y, challenge, response}`, `branch1` (same). Sets httponly `session` cookie on success. |
| `POST` | `/logout` | Clears `session` cookie. |

### Vault — `/api/vault` *(requires authentication)*

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/entries` | All entries for the authenticated user: `id`, `title`, `ciphertext`, `nonce`. |
| `POST` | `/entries` | Body: `title`, `ciphertext` (hex), `nonce` (hex). |
| `GET` | `/entries/<id>` | Single entry by ID. |
| `DELETE` | `/entries/<id>` | Delete entry. |

---

## Security

| Property | Mechanism |
|---|---|
| Authentication | OR-Schnorr ZKP (Fiat–Shamir) on secp256k1 |
| Password transmission | Never sent — proof only |
| Vault confidentiality | AES-256-GCM, client-side encryption |
| Key derivation | PBKDF2-HMAC-SHA256, 200 000 iterations |
| Session | JWT (HS256), httponly cookie, 1-hour expiry |
| User enumeration | `/init` returns random data for unknown usernames |
| Rate limiting | 200 req/hour per IP (Flask-Limiter, in-memory) |
| Content Security Policy | Per-request nonce; `script-src` / `style-src` nonce-restricted |
| Input validation | Pydantic schemas; 1 MB payload cap; non-JSON `Content-Type` rejected |

---

## Technology Stack

| Area | Library / Tool |
|---|---|
| Language | Python 3.12 |
| Web framework | Flask 3.1 |
| Cryptography (server) | `py-ecc` (secp256k1), `cryptography` (AES-GCM, HKDF, PBKDF2) |
| Cryptography (client) | Web Crypto API, native `BigInt` secp256k1 |
| Authentication | JWT via `PyJWT`, OR-Schnorr ZKP |
| Validation | Pydantic 2 |
| Storage | SQLite (`sqlite3`) |
| Rate limiting | Flask-Limiter 4 |
| CORS | flask-cors |
| Templating | Jinja2 |

---

## Running

```bash
pip install -r requirements.txt
python main.py
```

On first run, `JWT_SECRET` and `VAULT_MASTER_SECRET` are generated automatically and appended to `.env`. The database `data/vault.db` is created automatically.

Default: `http://0.0.0.0:5000`.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | auto-generated | HMAC-SHA256 signing key for JWT tokens. |
| `VAULT_MASTER_SECRET` | auto-generated | AES-GCM key for encrypting stored `encrypted_secret` values. |
| `HOST` | `0.0.0.0` | Bind address. |
| `PORT` | `5000` | Bind port. |
| `DEBUG` | `false` | Flask debug mode. |
