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
```

### Database (Docker Swarm)

```bash
# Initialize Docker Swarm (skip if already initialized)
docker swarm init

# Deploy PostgreSQL
docker stack deploy -c docker-compose.db.yml aegis-db

# Verify it's running
docker stack services aegis-db

# Start the app
npm run start:dev
```

#### Useful Docker Commands

| Command | Description |
|---|---|
| `docker stack services aegis-db` | Check service status |
| `docker service logs aegis-db_postgres` | View database logs |
| `docker stack rm aegis-db` | Stop the database |
| `docker ps -f name=aegis-db` | List running containers |

## Scripts

| Command | Description |
|---|---|
| `npm run start:dev` | Start in watch mode |
| `npm run build` | Compile |
| `npm run test` | Unit tests |
| `npm run test:e2e` | E2E tests |
| `npm run lint` | Lint + fix |
