# Zero-Knowledge Cloud Storage API

FastAPI and PostgreSQL backend for authenticated encrypted-blob storage.
The server stores ciphertext and encryption metadata; encryption and decryption
belong on the client.

## Setup

Create a virtual environment, then install runtime and development packages:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
```

Copy `.env.example` to `.env` and provide separate development and test
database URLs. The test database name must contain `test`.

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
