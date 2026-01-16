# Aegis Auth Service

**A production-grade, centralized authentication and identity service built with Clean Architecture.**

Aegis is a reusable authentication microservice designed to serve as the single source of truth for identity across multiple backend services written in any language. It provides JWT-based authentication with asymmetric key signing (RS256), enabling other services to verify tokens locally without additional network calls.

---

## 🎯 Key Features

- **Language-Agnostic Integration** – Other services verify JWT tokens locally using JWKS
- **RS256 Asymmetric Signing** – Secure JWT signing with public/private key pairs
- **Refresh Token Rotation** – Automatic token refresh with revocation support
- **Clean Architecture** – Domain-driven design with clear separation of concerns
- **Production-Ready Design** – Type-safe, scalable, and optimized for real-world use
- **Docker Support** – Containerized deployment with PostgreSQL
- **JWKS Endpoint** – Public key distribution via `/.well-known/jwks.json`

---

## 🏗️ Architecture

```
src/
├── domain/                 # Pure TypeScript - no framework dependencies
│   ├── entities/           # User, RefreshToken (plain classes)
│   ├── repositories/       # Repository interfaces
│   ├── value-objects/      # Email, Password VOs
│   └── exceptions/         # Domain-specific exceptions
│
├── application/            # Business logic and use cases
│   ├── use-cases/          # RegisterUser, Login, RefreshToken, etc.
│   ├── ports/              # ILogger, IPasswordHasher, IJwtService
│   └── dtos/               # Input/output data transfer objects
│
├── infrastructure/         # Framework and external implementations
│   ├── persistence/        # TypeORM entities and repositories
│   ├── security/           # JWT, password hashing, key management
│   ├── logging/            # Winston logger implementation
│   └── config/             # Environment configuration
│
├── interfaces/             # HTTP layer
│   ├── http/controllers/   # REST API controllers
│   ├── http/presenters/    # Response formatting
│   └── guards/             # JWT authentication guards
│
└── main.ts                 # Application entry point
```

### Clean Architecture Principles

- **Domain layer** has **zero dependencies** on NestJS, TypeORM, or any framework
- **Use cases** orchestrate business logic without knowing HTTP or database details
- **Infrastructure** implements domain interfaces (Dependency Inversion)
- **Interfaces** handle HTTP concerns and presentation logic

---

## 🛠️ Tech Stack

### Core Framework
- **NestJS** – Modular, enterprise-grade Node.js framework
- **TypeScript (Strict Mode)** – Type safety and developer experience

### Database & ORM
- **PostgreSQL** – Production-grade relational database
- **TypeORM** – TypeScript ORM with migration support

### Authentication & Security
- **JWT (RS256)** – Asymmetric key signing for distributed systems
- **bcrypt** – Password hashing with salt
- **Passport.js** – Authentication middleware

### Logging & Monitoring
- **Winston** – Production-grade logging with file rotation
- **Custom Logger Interface** – Framework-agnostic logging abstraction

### Development Tools
- **Docker & docker-compose** – Containerized development environment
- **ESLint & Prettier** – Code quality and formatting
- **Jest** – Unit and integration testing

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built with ❤️ for production environments**
