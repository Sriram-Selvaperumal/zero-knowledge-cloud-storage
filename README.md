# Prototype

Self-hosted zero-knowledge cloud storage prototype built with FastAPI,
PostgreSQL, React, and client-side authenticated encryption. The server stores
ciphertext, encrypted manifests, and wrapped keys only.

## Setup

Create a virtual environment, then install runtime and development packages:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
```

Copy `.env.example` to `.env` and provide separate development and test
database URLs. The test database name must contain `test`.

## Registration Email

Registration creates no user until a six-digit email code is verified. Add a
random `REGISTRATION_OTP_SECRET_KEY` and your SMTP settings to `.env`:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_EMAIL=no-reply@example.com
SMTP_STARTTLS=true
```

Use an SMTP app password where your email provider supports one. Never commit
real SMTP credentials. Codes expire after ten minutes, allow five attempts,
and have a configurable resend cooldown.

The registration API is a two-step flow:

- `POST /auth/register/request-otp`
- `POST /auth/register/verify`

## Database Migrations

For a new database:

```powershell
.\venv\Scripts\python.exe -m alembic upgrade head
```

For an existing database that was created before Alembic and already contains
the current tables, mark it at the baseline once:

```powershell
.\venv\Scripts\python.exe -m alembic stamp head
```

Create future migrations with:

```powershell
.\venv\Scripts\python.exe -m alembic revision --autogenerate -m "describe change"
```

## Tests

Tests refuse to run against `DATABASE_URL`. Set `TEST_DATABASE_URL` to a
separate PostgreSQL database whose name contains `test`, then run:

```powershell
.\venv\Scripts\python.exe -m pytest
```

## Run the API

```powershell
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Swagger documentation is available at `http://127.0.0.1:8000/docs`.

## Run the Client

Install and start the React client:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

The client is available at `http://127.0.0.1:5173`.

## End-To-End Encryption Protocol

Protocol version 1 uses:

- Argon2id to derive a password-based key-encryption key.
- A random 256-bit vault key wrapped by that derived key.
- A random 256-bit key for every file.
- XChaCha20-Poly1305 secret streams with 4 MiB plaintext chunks.
- Authenticated wrapping for file keys and encrypted file manifests.
- Client-generated file identifiers bound into authenticated data.

Vault keys exist only in browser memory. The server stores the wrapped vault
profile, encrypted file bytes, wrapped file keys, and versioned public
encryption parameters. Losing the vault password makes encrypted files
unrecoverable.

Run frontend crypto tests and the production build with:

```powershell
cd frontend
npm.cmd test
npm.cmd run build
```
