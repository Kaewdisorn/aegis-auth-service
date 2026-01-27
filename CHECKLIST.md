# Aegis Auth Service - Project Checklist

> A production-grade, centralized authentication and identity service.

**Last Updated:** January 27, 2026

---

## 🏗️ Project Setup

### Infrastructure
- [x] NestJS project initialized
- [x] TypeScript strict mode configured
- [x] ESLint & Prettier configured
- [x] Jest testing framework configured
- [x] Docker Compose with PostgreSQL
- [x] Environment configuration (`.env`)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Production Dockerfile

### Clean Architecture Structure
- [x] `src/application/` - Use cases & ports
- [ ] `src/domain/` - Entities, repositories, value objects
- [x] `src/infrastructure/` - Framework implementations
- [x] `src/interfaces/` - HTTP controllers

---

## 📝 Application Ports (Interfaces)

### Completed
- [x] `ILogger` - Logging abstraction
- [x] `IAppConfig` - Configuration abstraction

### TODO
- [ ] `IUserRepository` - User persistence interface
- [ ] `IRefreshTokenRepository` - Token persistence interface
- [ ] `IPasswordHasher` - Password hashing interface
- [ ] `IJwtService` - JWT operations interface
- [ ] `IKeyManager` - RSA key management interface

---

## 🏛️ Domain Layer

### Entities (Plain TypeScript - No Decorators)
- [ ] `User` - User entity
- [ ] `RefreshToken` - Refresh token entity

### Value Objects
- [ ] `Email` - Email validation
- [ ] `Password` - Password rules & validation
- [ ] `UserId` - User identifier

### Repository Interfaces
- [ ] `IUserRepository`
- [ ] `IRefreshTokenRepository`

### Domain Exceptions
- [ ] `UserNotFoundException`
- [ ] `InvalidCredentialsException`
- [ ] `TokenExpiredException`
- [ ] `UserAlreadyExistsException`

---

## 💼 Application Layer (Use Cases)

### Authentication Use Cases
- [ ] `RegisterUserUseCase`
- [ ] `LoginUseCase`
- [ ] `LogoutUseCase`
- [ ] `RefreshTokenUseCase`
- [ ] `ValidateTokenUseCase`

### User Management Use Cases
- [ ] `GetUserProfileUseCase`
- [ ] `ChangePasswordUseCase`
- [ ] `ResetPasswordUseCase` (optional)

### DTOs
- [ ] `RegisterUserDto`
- [ ] `LoginDto`
- [ ] `TokenResponseDto`
- [ ] `UserProfileDto`

---

## 🔧 Infrastructure Layer

### Configuration
- [x] `AppConfigService` - Environment configuration
- [x] `IAppConfig` interface with `AppConfig`, `LoggerConfig`
- [ ] `DatabaseConfig` - Database configuration
- [ ] `JwtConfig` - JWT configuration

### Logging
- [x] `WinstonLoggerService` - Winston implementation
- [x] `LoggerModule` - Global logger module
- [x] PII sanitization (password, token, apiKey, etc.)
- [x] Metadata enrichment (environment, serviceName, hostname, pid)
- [x] Daily rotating file transports
- [x] Environment-based formatting (dev: pretty, prod: JSON)

### Exception Filters
- [x] `GlobalExceptionFilter` - Catches all exceptions
- [x] `HttpExceptionFilter` - Handles HTTP exceptions
- [x] Correlation ID generation
- [x] Standardized error response format
- [x] Header sanitization

### Middleware
- [ ] `CorrelationIdMiddleware` - Request tracing
- [ ] `HttpLoggerMiddleware` - Request/response logging

### Persistence (TypeORM)
- [ ] `TypeOrmUserRepository` - User repository implementation
- [ ] `TypeOrmRefreshTokenRepository` - Token repository implementation
- [ ] `UserEntity` - TypeORM entity (ORM decorators)
- [ ] `RefreshTokenEntity` - TypeORM entity
- [ ] Database migrations

### Security
- [ ] `BcryptPasswordHasher` - Password hashing
- [ ] `JwtTokenService` - JWT sign/verify (RS256)
- [ ] `KeyManager` - RSA key pair management
- [ ] `JwksService` - JWKS endpoint generation

---

## 🌐 Interfaces Layer (HTTP)

### Auth Controller
- [x] `AuthController` - Basic structure
- [ ] `POST /auth/register` - User registration
- [ ] `POST /auth/login` - User login
- [ ] `POST /auth/logout` - User logout
- [ ] `POST /auth/refresh` - Token refresh
- [ ] `GET /auth/me` - Get current user profile

### JWKS Endpoint
- [ ] `GET /.well-known/jwks.json` - Public keys for JWT verification

### Guards
- [ ] `JwtAuthGuard` - Protect routes
- [ ] `RefreshTokenGuard` - Validate refresh tokens

### Presenters
- [ ] `AuthPresenter` - Format auth responses
- [ ] `UserPresenter` - Format user responses

---

## 🔐 JWT & Security

### RS256 Asymmetric Keys
- [ ] RSA key pair generation
- [ ] Private key storage (secure)
- [ ] Public key exposure via JWKS
- [ ] Key rotation support (optional)

### Token Management
- [ ] Access token (short-lived: 15m)
- [ ] Refresh token (long-lived: 7d)
- [ ] Refresh token rotation
- [ ] Token revocation (logout)

---

## 🧪 Testing

### Unit Tests
- [x] `winston-logger.service.spec.ts`
- [x] `global-exception.filter.spec.ts`
- [x] `http-exception.filter.spec.ts`
- [ ] `correlation-id.middleware.spec.ts`
- [ ] `http-logger.middleware.spec.ts`
- [ ] Use case tests
- [ ] Repository tests

### Integration Tests
- [ ] Auth controller tests
- [ ] Database repository tests

### E2E Tests
- [x] `app.e2e-spec.ts` - Basic setup
- [ ] Auth flow E2E tests
- [ ] Token refresh E2E tests

---

## 📚 Documentation

- [x] `README.md` - Project overview
- [x] `.copilot-instructions.md` - AI assistant context
- [x] `PRODUCTION_LOGGING_PLAN.md` - Logging implementation plan
- [x] `CHECKLIST.md` - This file
- [ ] API documentation (Swagger/OpenAPI)
- [ ] Deployment guide
- [ ] Contributing guide

---

## 🚀 Deployment

- [x] Docker Compose (development)
- [ ] Production Docker image
- [ ] Kubernetes manifests (optional)
- [ ] Environment variable documentation
- [ ] Health check endpoint
- [ ] Graceful shutdown handling

---

## 📊 Progress Summary

| Layer | Status |
|-------|--------|
| Project Setup | 🟡 80% |
| Application Ports | 🟡 40% |
| Domain Layer | 🔴 0% |
| Application Use Cases | 🔴 0% |
| Infrastructure - Logging | ✅ 100% |
| Infrastructure - Filters | ✅ 100% |
| Infrastructure - Middleware | 🔴 0% |
| Infrastructure - Persistence | 🔴 0% |
| Infrastructure - Security | 🔴 0% |
| Interfaces - HTTP | 🟡 20% |
| Testing | 🟡 30% |
| Documentation | 🟡 60% |

---

## 🎯 Next Priority Tasks

1. **Domain Layer** - Create User entity and repository interface
2. **Infrastructure - Persistence** - TypeORM setup with PostgreSQL
3. **Infrastructure - Security** - JWT service with RS256
4. **Application Use Cases** - Register and Login
5. **HTTP Endpoints** - Auth controller implementation

---

## 📝 Notes

- Domain layer must have **zero dependencies** on NestJS/TypeORM
- Use **explicit interfaces** in `application/ports` for all external dependencies
- All sensitive data must be **sanitized** before logging
- JWT must use **RS256** (asymmetric) for distributed verification
- Follow **Clean Architecture** principles strictly
