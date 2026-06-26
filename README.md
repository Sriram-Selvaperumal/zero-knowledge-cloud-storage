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

Generate independent random values for `JWT_SECRET_KEY`,
`REGISTRATION_OTP_SECRET_KEY`, `REFRESH_TOKEN_SECRET_KEY`, and
`AUTH_THROTTLE_SECRET_KEY`. Keep them only in `.env`.

## Registration Email

Registration creates no user until a six-digit email code is verified. Add a
random `REGISTRATION_OTP_SECRET_KEY` and your SMTP settings to `.env`:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_EMAIL=no-reply@example.com
SMTP_AUTH=true
SMTP_STARTTLS=true
```

Use an SMTP app password where your email provider supports one. Never commit
real SMTP credentials. Codes expire after ten minutes, allow five attempts,
and have a configurable resend cooldown.

The registration API is a two-step flow:

- `POST /api/auth/register/request-otp`
- `POST /api/auth/register/verify`

## Account Security

- Access tokens are short-lived JWTs tied to revocable database sessions.
- Refresh tokens rotate in an HttpOnly cookie and are stored only as hashes.
- Logout revokes one session; logout-all revokes every session immediately.
- Five failed logins trigger a configurable temporary lockout.
- Password changes rewrap the vault key without re-encrypting stored files.
- Password recovery requires both an emailed OTP and the client-held recovery
  key.

Recovery keys are generated in the browser and shown once. The server stores
only a recovery-wrapped copy of the vault key. Existing accounts created before
this feature receive a recovery key after their next successful login.

## Encrypted Share Links

Authenticated owners can create password-protected links with one-day,
seven-day, thirty-day, or no expiration. The browser unwraps the selected
file key and rewraps it with an Argon2id key derived from the share password.
The server receives neither the password nor the plaintext file key.

Public access uses a throttled password proof. A successful proof returns a
short-lived download grant, while revoked and expired links stop working
immediately. The API supports creating, listing, and revoking shares:

- `POST /api/files/{file_id}/shares`
- `GET /api/files/{file_id}/shares`
- `DELETE /api/files/{file_id}/shares/{share_id}`
- `GET /api/shares/{token}`
- `POST /api/shares/{token}/unlock`
- `GET /api/shares/{token}/download`

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
- Password-derived wrapping for individual shared-file keys.
- Client-generated file identifiers bound into authenticated data.

Vault keys exist only in browser memory. The server stores wrapped vault
profiles, encrypted file bytes, wrapped file keys, and versioned public
encryption parameters. Losing both the password and recovery key makes
encrypted files unrecoverable.

Run frontend crypto tests and the production build with:

```powershell
cd frontend
npm.cmd test
npm.cmd run build
```
