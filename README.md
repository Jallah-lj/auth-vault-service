# Auth Vault Service

A secure, self-hostable backend MVP for user authentication and private credential-vault entries. It provides a versioned REST API, JWT access/refresh sessions, refresh-token rotation, and encrypted vault secrets.

## Stack

- **Python 3.12**, FastAPI, SQLAlchemy 2
- SQLite for quick local startup; PostgreSQL 16 for container deployments
- Argon2id password hashing
- Signed JWT access and refresh tokens
- Fernet authenticated encryption for each item's username, password, and notes

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
# Set AUTH_VAULT_JWT_SECRET and AUTH_VAULT_ENCRYPTION_KEY in .env
uvicorn app.main:app --reload
```

The interactive API documentation is at [http://localhost:8000/docs](http://localhost:8000/docs). The health endpoint is `GET /health`.

Run the test suite:

```bash
pytest
```

### Docker

Set the two required secrets, then start the service and PostgreSQL:

```bash
export AUTH_VAULT_JWT_SECRET="$(openssl rand -hex 32)"
export AUTH_VAULT_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
docker compose up --build
```

## API

All application routes are prefixed with `/api/v1`.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/auth/register` | Create an account and receive a token pair |
| POST | `/auth/login` | Authenticate and receive a token pair |
| POST | `/auth/refresh` | Rotate a refresh token |
| POST | `/auth/logout` | Revoke a refresh token |
| GET | `/auth/me` | Current user profile |
| POST | `/vault/items` | Create an encrypted vault entry |
| GET | `/vault/items` | List entry metadata (never returns secrets) |
| GET/PATCH/DELETE | `/vault/items/{item_id}` | Read, update, or remove one owned entry |

Protected routes require `Authorization: Bearer <access_token>`. Register and login accept:

```json
{ "email": "member@example.com", "password": "a-password-with-at-least-12-characters" }
```

Vault creates accept `title`, optional `url`, `username`, `password`, and `notes`.

## Security and deployment notes

- Passwords are never stored in plaintext; Argon2 hashes are stored instead.
- `username`, `password`, and `notes` are serialized then encrypted before they are persisted. Titles and URLs deliberately remain plaintext to make list views possible.
- Use **independent**, long, persistent values for `AUTH_VAULT_JWT_SECRET` and `AUTH_VAULT_ENCRYPTION_KEY`. Rotating the encryption key without a migration makes old vault fields unreadable.
- The fallback encryption key is only for local development. A production deployment must supply `AUTH_VAULT_ENCRYPTION_KEY`, terminate TLS at the service or proxy, restrict CORS origins, and use managed schema migrations rather than startup `create_all`.
- Refresh tokens are single-use: a successful refresh revokes the supplied token and issues a replacement.

## Layout

```text
app/api/       routes and authentication dependencies
app/core/      configuration and cryptographic primitives
app/db/        SQLAlchemy database setup and models
app/schemas/   request/response contracts
tests/         API integration coverage
```
