# User Registration - Implementation Checklist

## 1. Install Dependencies
- [ ] Install TypeORM & database driver (`@nestjs/typeorm`, `typeorm`, `pg`)
- [ ] Install validation packages (`class-validator`, `class-transformer`)
- [ ] Install password hashing library (`bcrypt`, `@types/bcrypt`)
- [ ] Install configuration module (`@nestjs/config`)

## 2. Domain Layer (`modules/user/domain/`)
- [ ] Create `User` entity (id, email, password, firstName, lastName, isActive, createdAt, updatedAt)
- [ ] Create `UserRepository` interface (port)
- [ ] Create domain exceptions (e.g., `UserAlreadyExistsException`)
- [ ] Create value objects if needed (e.g., `Email`, `Password`)

## 3. Application Layer (`modules/user/application/`)
- [ ] Create `RegisterUserDto` (input validation with class-validator)
- [ ] Create `RegisterUserUseCase` / `RegisterUserService`
- [ ] Implement registration logic:
  - [ ] Check if user already exists by email
  - [ ] Hash password with bcrypt
  - [ ] Save user to database
  - [ ] Return created user (without password)
- [ ] Create `UserResponseDto` (output mapping)

## 4. Infrastructure Layer (`modules/user/infrastructure/`)
- [ ] Create `TypeOrmUserRepository` (implements UserRepository interface)
- [ ] Configure TypeORM module with database connection
- [ ] Create database migration for users table

## 5. Presentation Layer (`modules/user/presentation/`)
- [ ] Create `UserController` with `POST /users/register` endpoint
- [ ] Add request validation pipe
- [ ] Add proper HTTP status codes (201 Created)
- [ ] Add Swagger/OpenAPI decorators (optional)

## 6. Module Wiring
- [ ] Register providers in `UserModule`
- [ ] Import `UserModule` in `AppModule`
- [ ] Configure database connection in `app.module.ts` or config

## 7. Configuration & Environment
- [ ] Create `.env` file with DB credentials
- [ ] Add `.env` to `.gitignore`
- [ ] Create `.env.example` as template

## 8. Testing
- [ ] Unit test: `RegisterUserUseCase`
- [ ] Unit test: password hashing logic
- [ ] Unit test: `UserController`
- [ ] E2E test: `POST /users/register` (happy path)
- [ ] E2E test: duplicate email rejection
- [ ] E2E test: invalid input validation

## 9. Final Review
- [ ] Verify error responses are consistent
- [ ] Ensure no password leaks in responses
- [ ] Check input sanitization
- [ ] Confirm rate limiting considerations
