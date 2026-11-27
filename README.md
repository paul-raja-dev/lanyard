# Lanyard Auth Service

A lightweight **OAuth 2.0-style authentication service** built with FastAPI.  
Issues RS256-signed JWT access tokens and rotating refresh tokens.

---

## Features

| Feature | Detail |
|---|---|
| **RS256 JWT** | Asymmetric signing; public key exposed via JWKS |
| **Refresh token rotation** | Old token is revoked on every refresh |
| **Password hashing** | Argon2 via `pwdlib` |
| **Multi-tenant** | Client applications register with a unique `client_id` |
| **SQLite / SQLAlchemy** | Swap to Postgres with a one-line `DATABASE_URL` change |

---

## Project Structure

```
lanyard/
├── app/
│   ├── config.py        # Pydantic-settings (reads .env)
│   ├── database.py      # SQLAlchemy models & session
│   ├── schemas.py       # Pydantic request/response schemas
│   ├── security.py      # JWT, password, and token helpers
│   ├── main.py          # App factory + lifespan + system routes
│   └── routes/
│       ├── auth.py      # /register  /login  /refresh  /logout
│       └── apps.py      # /apps
├── scripts/
│   └── generate_keys.py # One-time RSA key-pair generator
├── .env.example
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate RSA keys

```bash
python scripts/generate_keys.py
```

This writes `private.pem` and `public.pem` to the project root (both are gitignored).

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env as needed
```

### 4. Run the server

```bash
uvicorn app.main:app --reload
```

Interactive docs: <http://localhost:8000/docs>

---

## API Reference

### System

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/.well-known/jwks.json` | RS256 public key set |

### Applications

| Method | Path | Description |
|---|---|---|
| `POST` | `/apps` | Register a client application |

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/register` | Create a user account |
| `POST` | `/login` | Authenticate → access + refresh tokens |
| `POST` | `/refresh` | Rotate refresh token → new token pair |
| `POST` | `/logout` | Revoke a refresh token |

---

## Token Flow

```
Client                        Lanyard
  │  POST /login              │
  │ ─────────────────────────►│
  │  { access_token, refresh_token }
  │ ◄─────────────────────────│
  │                           │
  │  (access_token expires)   │
  │  POST /refresh            │
  │ ─────────────────────────►│  old refresh revoked
  │  { new access_token, new refresh_token }
  │ ◄─────────────────────────│
```

---

## Security Notes

- **`private.pem` and `.env` are gitignored** — never commit them.
- Refresh tokens are stored **hashed** (SHA-256); raw tokens never touch the DB.
- Access tokens expire in **15 minutes** by default; adjust via `ACCESS_TOKEN_EXPIRE_MINUTES`.
