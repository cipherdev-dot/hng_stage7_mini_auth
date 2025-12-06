# Mini Authentication System

A FastAPI-based authentication system supporting both user JWT authentication and service-to-service API key authentication.

## Features

- **User Authentication**: JWT-based login for users
- **API Key Management**: Create secure API keys for service-to-service access
- **Middleware Detection**: Automatically detects Bearer tokens (users) or X-API-Key headers (services)
- **Protected Routes**: Routes that require specific authentication types
- **Expiration & Revocation**: API keys expire after 1 year and can be revoked

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set up PostgreSQL database

3. Create `.env` file:
   ```
   DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/miniauth
   SECRET_KEY=your-super-secret-jwt-key-change-in-production
   API_KEY_SALT=another-secure-salt-for-api-keys
   ```

4. Run the application:
   ```bash
   uvicorn main:app --reload
   ```

5. Access API docs: http://127.0.0.1:8000/docs

## Endpoints

### Authentication
- `POST /api/v1/auth/signup` - Register new user
- `POST /api/v1/auth/login` - Login and get JWT token

### API Keys
- `POST /api/v1/keys/create` - Create new API key (requires auth)

### Protected Routes
- `GET /api/v1/protected/user` - User-only access (JWT)
- `GET /api/v1/protected/service` - User or service access

## Usage

### User Authentication
```bash
# Signup
curl -X POST "http://localhost:8000/api/v1/auth/signup" -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"password"}'

# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" -H "Content-Type: application/json" -d '{"email":"user@example.com","password":"password"}'
# Returns {"access_token":"ey...", "token_type":"bearer"}
```

### API Key Creation
```bash
# With JWT
curl -X POST "http://localhost:8000/api/v1/keys/create" -H "Authorization: Bearer <jwt-token>"
# Returns {"id":"uuid", "key":"generated-key", "expires_at":"2025-..."}
```

### Protected Endpoints
```bash
# User-only access with JWT
curl -X GET "http://localhost:8000/api/v1/protected/user" -H "Authorization: Bearer <jwt-token>"

# Service access with API key
curl -X GET "http://localhost:8000/api/v1/protected/service" -H "X-API-Key: <api-key>"
```

## Architecture

The `get_current_user_or_service` function acts as middleware, checking headers in order:
1. `Authorization: Bearer <token>` - Validates JWT and returns user
2. `X-API-Key: <key>` - Validates API key and returns associated user

Returns tuple: `(user, auth_type)` where `auth_type` is "user" or "service".
