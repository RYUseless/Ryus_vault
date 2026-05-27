# 🔐 Ryus Vault

> **A self-hosted password vault where the server never learns your password.**  
> *(A server tvůj heslo nikdy neuvidí — doslova.)*

---

## What is this?

Ryus Vault is a self-hosted, end-to-end encrypted password manager built on top of some genuinely interesting cryptography. The headline feature: authentication uses a **zero-knowledge proof** — you prove to the server that you know your secret without ever transmitting it. The server stores a public key, verifies a mathematical proof, and that's it.

Your vault entries are encrypted **in the browser** before hitting the network. The server stores ciphertext it cannot read.

---

## ✨ The Cool Part — Fiat-Shamir OR-Schnorr ZKP

### Laicky verze 🇨🇿

Představ si, že chceš dokázat, že znáš heslo, aniž bys ho komukoliv řekl. Normálně to nejde — buď heslo pošleš, nebo nedokážeš nic. Ale s **zero-knowledge proofem (ZKP)** to jde.

Konkrétně tady funguje toto: místo hesla pošleš **matematický důkaz** postavený na eliptické křivce **secp256k1** (jo, ta samá jako Bitcoin). Důkaz říká: *„Existuje tajná hodnota, která odpovídá tomuto veřejnému klíči"* — ale samotná tajná hodnota zůstane navždy u tebe.

Celé to probíhá v prohlížeči. Na server letí jen čísla.

---

### Technical version 🇬🇧

Authentication is built on an **OR-Schnorr protocol**, made non-interactive via the **Fiat-Shamir heuristic**.

Here's the flow:

```
Client                                    Server
──────                                    ──────
password + salt  →  PBKDF2 (200k rounds)
                 →  secret (256-bit integer)
                 →  public key = secret × G  (secp256k1)

                         [registration: public key stored]

Login:
  1. fetch salt + dummy_public_key from /init
  2. compute OR-proof:
     ┌─ branch0 (real):  r ← random nonce
     │                   R0 = r·G
     │                   c0 = c_total − c1
     │                   s0 = r − c0·secret
     └─ branch1 (dummy): c1, s1 ← random
                         R1 = s1·G + c1·dummy_pk   ← simulated
  3. Fiat-Shamir challenge:
     c_total = SHA-256(R0 ∥ R1 ∥ real_pk ∥ dummy_pk ∥ username)

  4. send proof (R0, c0, s0, R1, c1, s1) → server

Server verifies:
  c0 + c1 ≡ c_total  (mod ORDER)
  s0·G + c0·real_pk  == R0  ✓
  s1·G + c1·dummy_pk == R1  ✓
```

The OR construction means the prover convinces the verifier they know **one of two** secrets — the real key, or the dummy key the server generates and forgets. It looks identical from the outside. This prevents the server from learning *which* branch was real.

**The password never crosses the wire. Not as plaintext, not as a hash. Never.**

---

## 🗄️ Vault Encryption

After authentication you get a session token. But your vault entries are still encrypted — the server can't read them even with a valid session.

```
secret (your derived key)
    │
    └── HKDF-SHA256 (info: "ryus-vault-key", salt: per-user)
              │
              └── 256-bit AES-GCM key
                      │
                      ├── encrypt(entry) → ciphertext + nonce
                      └── decrypt(ciphertext, nonce) → plaintext
```

Encryption and decryption happen entirely in the browser via the **Web Crypto API**. The `crypto.js` module implements secp256k1 point arithmetic from scratch using `BigInt` — no external crypto libraries on the client.

---

## 🏗️ Architecture

```
Ryus_vault/
├── src/
│   ├── crypto/
│   │   ├── domain/          # abstract interfaces (SchnorrProtocol, VaultCipher)
│   │   └── implementation/  # SchnorrProtocolImpl (py-ecc/secp256k1)
│   │                        # VaultCipherImpl (AES-256-GCM + HKDF)
│   ├── backend/
│   │   ├── domain/          # User, VaultEntry, repositories
│   │   └── implementation/  # SQLite-backed repos
│   ├── api/
│   │   ├── routes/          # /auth (init, register, login, logout)
│   │   │                    # /vault (CRUD entries)
│   │   └── middleware/      # JWT auth, rate limiting
│   └── web/
│       └── static/js/
│           ├── crypto.js    # secp256k1 + WebCrypto (client-side)
│           ├── login.js     # OR-proof generation in browser
│           └── vault.js     # encrypt/decrypt vault entries
```

Clean Architecture — domain knows nothing about Flask, SQLite, or `py-ecc`. Implementations are swappable.

---

## 🛠️ Stack

| Layer | Tech |
|---|---|
| Backend | Python · Flask 3 · Pydantic |
| Crypto (server) | `py-ecc` (secp256k1) · `cryptography` (AES-GCM, HKDF) |
| Crypto (client) | Vanilla JS · Web Crypto API · BigInt |
| Auth | Zero-knowledge OR-Schnorr · JWT (httponly cookie) |
| Storage | SQLite |
| Rate limiting | Flask-Limiter |

---

## 🚀 Running it

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set secrets
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
export VAULT_MASTER_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

# 3. Run
python main.py
```

By default serves on `0.0.0.0:5000`. Set `HOST`, `PORT`, `DEBUG` env vars to override.

---

## 🔒 Security Properties

| Property | Status |
|---|---|
| Password never sent to server | ✅ ZKP — mathematically guaranteed |
| Vault data encrypted at rest | ✅ AES-256-GCM, server only sees ciphertext |
| Replay attack resistance | ✅ Schnorr nonce is random per proof |
| Username enumeration resistance | ✅ `/init` returns dummy data for unknown users |
| Brute-force resistance | ✅ PBKDF2 (200 000 iterations) + Flask-Limiter |
| No password hashes to leak | ✅ Server stores EC public key, not a hash |

---

## 📐 The Math (if you want it)

The Fiat-Shamir transform converts an interactive Schnorr identification scheme into a non-interactive proof by replacing the verifier's random challenge with a hash of the transcript:

```
Interactive Schnorr:        Non-interactive (Fiat-Shamir):
  Prover → R = r·G            same, but c = H(R ∥ pk ∥ msg)
  Verifier → c (random)       no verifier needed
  Prover → s = r − c·x        proof = (R, c, s)
  Verify: s·G + c·pk == R
```

The OR construction (Cramer-Damgård-Schoenmakers 1994) lets a prover simulate one branch while producing a real proof for the other, such that both look identical. The constraint `c0 + c1 = c_total` ties them together and cannot be faked without knowing at least one secret.

Curve used: **secp256k1** — 256-bit prime field, group order ≈ 2²⁵⁶, same parameters as Bitcoin/Ethereum.

---

*Made for the purpose of exploring applied zero-knowledge cryptography.*
