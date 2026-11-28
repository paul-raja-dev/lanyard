# Lanyard Auth Service

A lightweight **OAuth 2.0-style authentication service** built with FastAPI.  
Issues RS256-signed JWT access tokens, rotating refresh tokens with reuse detection, multi-key JWKS rotation, Redis-backed rate limiting, and admin-only audit logging.

---

## Features

| Feature | Detail |
|---|---|
| **RS256 JWT + Multi-Key JWKS** | Asymmetric signing with `kid` headers; all active and retiring public keys served dynamically at `/.well-known/jwks.json` |
| **Refresh Token Rotation & Reuse Detection** | Tokens are grouped into families (`family_id`); replaying a revoked token invalidates the entire family and forces logout |
| **Password Hashing** | Argon2 via `pwdlib` |
| **Multi-Tenant Client Apps** | Client applications register with a unique `client_id` |
| **PostgreSQL + Alembic** | SQLAlchemy ORM backed by PostgreSQL with versioned Alembic migrations |
| **Redis-Backed Rate Limiting** | Configurable per-endpoint throttling via `slowapi` (dual IP + email limiting on `/login`) |
| **Audit Logging Middleware** | Logs every request/response (`X-Request-ID`, method, path, status, IP, `user_id`, duration) to stdout and PostgreSQL `audit_logs` |
| **Lanyard Admin Access** | Admin users (`is_admin=True`) verified via RS256 Bearer JWTs can query `/admin/logs` |

---

## Project Structure

```text
lanyard/
├── alembic/
│   ├── env.py
│   └── versions/
│       ├── 0001_initial_schema.py
│       └── 0002_add_admin_and_audit_logs.py
├── app/
│   ├── config.py          # Pydantic-settings (reads .env)
│   ├── database.py        # SQLAlchemy models & session
│   ├── dependencies.py    # Admin Bearer JWT guard (require_admin)
│   ├── limiter.py         # SlowAPI + Redis rate limiter & IP/email keys
│   ├── main.py            # App factory, lifespan, middleware, system routes
│   ├── middleware.py      # HTTP request/audit logging middleware
│   ├── schemas.py         # Pydantic request/response schemas
│   ├── security.py        # JWT, JWKS, password, and token helpers
│   └── routes/
│       ├── admin.py       # /admin/logs (admin only)
│       ├── apps.py        # /apps
│       └── auth.py        # /register  /login  /refresh  /logout
├── scripts/
│   ├── create_admin.py    # Create or promote a Lanyard admin user
│   └── generate_keys.py   # Generate RSA-2048 key pairs by kid
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

### 2. Configure environment

```bash
cp .env.example .env
# Set DATABASE_URL (PostgreSQL) and REDIS_URL in .env
```

### 3. Generate RSA keys

```bash
python scripts/generate_keys.py --kid auth-key-1
```

This writes `keys/auth-key-1.private.pem` (`0600`) and `keys/auth-key-1.public.pem` (all `*.pem` files are gitignored).

### 4. Run database migrations

```bash
alembic upgrade head
```

### 5. (Optional) Create a Lanyard admin user

```bash
python scripts/create_admin.py --email admin@lanyard.dev --password "your-strong-password"
```

### 6. Run the server

```bash
uvicorn app.main:app --reload
```

Interactive docs: <http://localhost:8000/docs>

---

## API Reference

### System

| Method | Path | Rate Limit | Description |
|---|---|---|---|
| `GET` | `/health` | Unthrottled | Health check (excluded from DB audit logs) |
| `GET` | `/.well-known/jwks.json` | Unthrottled | RS256 public key set (multi-key JWKS) |

### Applications

| Method | Path | Rate Limit | Description |
|---|---|---|---|
| `POST` | `/apps` | `5/minute` | Register a client application |

### Auth

| Method | Path | Rate Limit | Description |
|---|---|---|---|
| `POST` | `/register` | `5/minute` | Create a user account |
| `POST` | `/login` | `10/minute` (IP + email) | Authenticate -> access + refresh tokens |
| `POST` | `/refresh` | `30/minute` | Rotate refresh token (with reuse detection) |
| `POST` | `/logout` | `20/minute` | Revoke the entire refresh token family |

### Admin (Bearer JWT with `is_admin=True`)

| Method | Path | Description |
|---|---|---|
| `GET` | `/admin/logs` | Query paginated `audit_logs` (filterable by `method`, `path`, `status_code`, `user_id`, `client_ip`) |

---

## Key Rotation (Multi-Key JWKS)

1. Generate a new key pair:
   ```bash
   python scripts/generate_keys.py --kid auth-key-2
   ```
2. Update `ACTIVE_KEY_ID=auth-key-2` in `.env` and restart/reload the server. New tokens are signed with `auth-key-2`, while `/.well-known/jwks.json` serves both `auth-key-1` and `auth-key-2`.
3. Once all tokens signed with `auth-key-1` have expired (15 minutes by default), remove `keys/auth-key-1.private.pem` and `keys/auth-key-1.public.pem`.

---

## Token Flow & Reuse Detection

```text
Client                        Lanyard
  |  POST /login              |
  | ------------------------> |  new family_id created
  |  { access_token, RT-1 }   |
  | <------------------------ |
  |                           |
  |  POST /refresh (RT-1)     |
  | ------------------------> |  RT-1 revoked, RT-2 issued (same family_id)
  |  { access_token, RT-2 }   |
  | <------------------------ |
  |                           |
  |  POST /refresh (RT-1)     |  [Replayed revoked token]
  | ------------------------> |  Entire family_id revoked -> 401
  |  401 Security alert       |  (RT-2 is now also invalid)
  | <------------------------ |
```

---

## Security Notes

- **`.env`, `*.pem`, and `alembic.ini` are gitignored** — never commit credentials or private keys.
- Refresh tokens are stored **hashed** (SHA-256); raw tokens never touch the database.
- Access tokens expire in **15 minutes** by default; adjust via `ACCESS_TOKEN_EXPIRE_MINUTES`.
- `POST /register` always creates non-admin users (`is_admin=False`); admins can only be created or promoted via `scripts/create_admin.py`.
