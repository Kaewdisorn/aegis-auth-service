# Aegis Auth Service

**A production-grade, centralized authentication and identity service built with Clean Architecture.**

Aegis is a reusable authentication microservice designed to serve as the single source of truth for identity across multiple backend services written in any language. It provides JWT-based authentication with asymmetric key signing (RS256), enabling other services to verify tokens locally without additional network calls.

---

## 🎯 Key Features

- **Language-Agnostic Integration** – Other services verify JWT tokens locally using JWKS
- **RS256 Asymmetric Signing** – Secure JWT signing with public/private key pairs
- **Refresh Token Rotation** – Automatic token refresh with revocation support
- **Clean Architecture** – Domain-driven design with clear separation of concerns
- **Production-Ready Logging** – Winston with daily rotation, PII sanitization, structured metadata
- **Centralized Error Handling** – Global exception filters with correlation ID tracking
- **Type-Safe Configuration** – IAppConfig interface for centralized environment config
- **Docker Support** – Containerized deployment with PostgreSQL
- **JWKS Endpoint** – Public key distribution via `/.well-known/jwks.json`

---

## 🏗️ Architecture

```
src/
├── application/            # Business logic layer
│   ├── use-cases/          # RegisterUser, Login, RefreshToken, etc.
│   ├── ports/              # ILogger, IAppConfig, IPasswordHasher, IJwtService
│   └── dtos/               # Input/output data transfer objects
│
├── domain/                 # Pure TypeScript - no framework dependencies
│   ├── entities/           # User, RefreshToken (plain classes)
│   ├── repositories/       # Repository interfaces
│   ├── value-objects/      # Email, Password VOs
│   └── exceptions/         # Domain-specific exceptions
│
├── infrastructure/         # Framework and external implementations
│   ├── config/             # AppConfigService, environment configuration
│   ├── filters/            # GlobalExceptionFilter, HttpExceptionFilter
│   ├── logging/            # WinstonLoggerService implementation
│   ├── middleware/         # CorrelationId, HttpLogger (planned)
│   ├── persistence/        # TypeORM entities and repositories
│   └── security/           # JWT, password hashing, key management
│
├── interfaces/             # HTTP layer
│   └── http/
│       ├── controllers/    # REST API controllers
│       └── presenters/     # Response formatting
│
└── main.ts                 # Application entry point
```

### Clean Architecture Principles

- **Domain layer** has **zero dependencies** on NestJS, TypeORM, or any framework
- **Application ports** define interfaces (ILogger, IAppConfig) - no implementation details
- **Infrastructure** implements domain/application interfaces (Dependency Inversion)
- **Interfaces** handle HTTP concerns and presentation logic

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|------------|
| **Framework** | NestJS |
| **Language** | TypeScript (Strict Mode) |
| **Database** | PostgreSQL |
| **ORM** | TypeORM |
| **Authentication** | JWT (RS256), bcrypt, Passport.js |
| **Logging** | Winston, winston-daily-rotate-file |
| **Testing** | Jest |
| **Containerization** | Docker, docker-compose |
| **Code Quality** | ESLint, Prettier |

---

## ⚙️ Environment Variables

```bash
# Application
PORT=3000
HOST=localhost
NODE_ENV=development    # development | production

# Logging
LOG_LEVEL=info          # debug | info | warn | error
LOG_DIR=./logs
ENABLE_FILE_LOGGING=false

# Database
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=aegis_auth
POSTGRES_USER=aegis
POSTGRES_PASSWORD=aegis_password
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built with ❤️ for production environments**
