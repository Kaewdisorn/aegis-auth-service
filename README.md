# Aegis Auth Service

Authentication microservice built with NestJS.

## Tech Stack

- **Runtime:** Node.js + TypeScript
- **Framework:** NestJS 11
- **Database:** PostgreSQL + TypeORM
- **Validation:** class-validator + class-transformer
- **Auth:** bcrypt (password hashing)
- **Testing:** Jest + Supertest

## Architecture

Clean Architecture with the following layers per module:

```
src/
├── modules/
│   └── user/
│       ├── domain/              # Entities, repository interfaces, exceptions
│       ├── application/         # Use cases, DTOs
│       ├── infrastructure/      # TypeORM repository implementations
│       └── presentation/        # Controllers
└── shared/                      # Cross-cutting concerns
```

## Setup

```bash
npm install
cp .env.example .env   # configure DB credentials
npm run start:dev
```

## Scripts

| Command | Description |
|---|---|
| `npm run start:dev` | Start in watch mode |
| `npm run build` | Compile |
| `npm run test` | Unit tests |
| `npm run test:e2e` | E2E tests |
| `npm run lint` | Lint + fix |
