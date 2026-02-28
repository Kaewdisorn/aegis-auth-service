# PostgreSQL on Docker Swarm - Setup Checklist

---

## 1. Initialize Docker Swarm

- [ ] Initialize swarm mode (skip if already initialized)

```bash
docker swarm init
```

---

## 2. Create Docker Compose File

- [x] Create `docker-compose.db.yml` in project root

```yaml
version: "3.8"

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: ${DB_USERNAME:-postgres}
      POSTGRES_PASSWORD: ${DB_PASSWORD:-postgres}
      POSTGRES_DB: ${DB_DATABASE:-aegis_auth}
    ports:
      - "${DB_PORT:-5432}:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - aegis-network
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          memory: 512M

volumes:
  pgdata:
    driver: local

networks:
  aegis-network:
    driver: overlay
```

---

## 3. Create Environment Configuration

- [x] Create `.env` file (already in `.gitignore`)

```env
NODE_ENV=development

DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_DATABASE=aegis_auth
```

- [x] Create `.env.example`

```env
NODE_ENV=development

DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=
DB_PASSWORD=
DB_DATABASE=aegis_auth
```

---

## 4. Deploy PostgreSQL Stack

- [ ] Deploy the stack to Docker Swarm

```bash
docker stack deploy -c docker-compose.db.yml aegis-db
```

---

## 5. Verify Service Is Running

- [ ] Check stack services

```bash
docker stack services aegis-db
```

- [ ] Check container logs

```bash
docker service logs aegis-db_postgres
```

- [ ] Test database connection

```bash
docker exec -it $(docker ps -q -f name=aegis-db_postgres) psql -U postgres -d aegis_auth -c "SELECT 1;"
```

---

## 6. Useful Commands

- **Stop the stack:**

```bash
docker stack rm aegis-db
```

- **View running containers:**

```bash
docker ps -f name=aegis-db
```

- **Access psql shell:**

```bash
docker exec -it $(docker ps -q -f name=aegis-db_postgres) psql -U postgres -d aegis_auth
```

- **Inspect volume:**

```bash
docker volume inspect aegis-db_pgdata
```
