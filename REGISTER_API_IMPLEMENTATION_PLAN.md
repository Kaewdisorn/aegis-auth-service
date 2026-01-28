# Register API Implementation Plan
## Aegis Auth Service

**Date:** January 28, 2026  
**Status:** Ready for Implementation  
**Goal:** Implement user registration endpoint with Clean Architecture

---

## Overview

Build a complete user registration flow following Clean Architecture principles:
- **Domain Layer:** Pure TypeScript entities, value objects, repository interfaces
- **Application Layer:** Use cases, DTOs with validation
- **Infrastructure Layer:** TypeORM persistence, bcrypt password hashing
- **Interface Layer:** HTTP POST endpoint at `/auth/register`

---

## Prerequisites

### Install Dependencies
```bash
npm install @nestjs/typeorm typeorm pg bcrypt @nestjs/jwt class-validator class-transformer
npm install --save-dev @types/bcrypt
```

---

## Implementation Steps

### Phase 1: Domain Layer (Pure TypeScript - Zero Dependencies)

#### 1.1 Value Objects

**File: `src/domain/value-objects/user-id.vo.ts`**
```typescript
import { randomUUID } from 'crypto';

export class UserId {
  private constructor(public readonly value: string) {}

  static create(): UserId {
    return new UserId(randomUUID());
  }

  static fromString(id: string): UserId {
    if (!id || id.trim().length === 0) {
      throw new Error('UserId cannot be empty');
    }
    return new UserId(id);
  }

  equals(other: UserId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
```

**File: `src/domain/value-objects/email.vo.ts`**
```typescript
export class Email {
  private static readonly EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  private constructor(public readonly value: string) {}

  static create(email: string): Email {
    if (!email || !Email.EMAIL_REGEX.test(email)) {
      throw new Error('Invalid email format');
    }
    return new Email(email.toLowerCase().trim());
  }

  equals(other: Email): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
```

**File: `src/domain/value-objects/password.vo.ts`**
```typescript
export class Password {
  private static readonly MIN_LENGTH = 8;
  private static readonly MAX_LENGTH = 128;

  private constructor(public readonly value: string) {}

  /**
   * Creates a Password value object from plain text (for validation before hashing)
   */
  static create(plainPassword: string): Password {
    const errors = Password.validate(plainPassword);
    if (errors.length > 0) {
      throw new Error(`Invalid password: ${errors.join(', ')}`);
    }
    return new Password(plainPassword);
  }

  /**
   * Creates a Password value object from an already-hashed password (from DB)
   */
  static fromHash(hashedPassword: string): Password {
    if (!hashedPassword || hashedPassword.trim().length === 0) {
      throw new Error('Hashed password cannot be empty');
    }
    return new Password(hashedPassword);
  }

  private static validate(password: string): string[] {
    const errors: string[] = [];

    if (!password) {
      errors.push('Password is required');
      return errors;
    }

    if (password.length < Password.MIN_LENGTH) {
      errors.push(`Password must be at least ${Password.MIN_LENGTH} characters`);
    }

    if (password.length > Password.MAX_LENGTH) {
      errors.push(`Password must be at most ${Password.MAX_LENGTH} characters`);
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    return errors;
  }

  toString(): string {
    return '[REDACTED]';
  }
}
```

**File: `src/domain/value-objects/index.ts`**
```typescript
export * from './user-id.vo';
export * from './email.vo';
export * from './password.vo';
```

---

#### 1.2 Domain Entities

**File: `src/domain/entities/user.entity.ts`**
```typescript
import { UserId, Email } from '../value-objects';

export interface UserProps {
  id: UserId;
  email: Email;
  passwordHash: string;
  createdAt: Date;
  updatedAt: Date;
}

export class User {
  public readonly id: UserId;
  public readonly email: Email;
  public readonly passwordHash: string;
  public readonly createdAt: Date;
  public readonly updatedAt: Date;

  private constructor(props: UserProps) {
    this.id = props.id;
    this.email = props.email;
    this.passwordHash = props.passwordHash;
    this.createdAt = props.createdAt;
    this.updatedAt = props.updatedAt;
  }

  /**
   * Create a new User (for registration)
   */
  static create(email: Email, passwordHash: string): User {
    const now = new Date();
    return new User({
      id: UserId.create(),
      email,
      passwordHash,
      createdAt: now,
      updatedAt: now,
    });
  }

  /**
   * Reconstitute User from persistence
   */
  static reconstitute(props: UserProps): User {
    return new User(props);
  }

  /**
   * Returns a new User with updated password
   */
  changePassword(newPasswordHash: string): User {
    return new User({
      ...this.toProps(),
      passwordHash: newPasswordHash,
      updatedAt: new Date(),
    });
  }

  private toProps(): UserProps {
    return {
      id: this.id,
      email: this.email,
      passwordHash: this.passwordHash,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
    };
  }
}
```

**File: `src/domain/entities/index.ts`**
```typescript
export * from './user.entity';
```

---

#### 1.3 Repository Interfaces

**File: `src/domain/repositories/user.repository.interface.ts`**
```typescript
import { User } from '../entities';
import { Email, UserId } from '../value-objects';

export interface IUserRepository {
  findById(id: UserId): Promise<User | null>;
  findByEmail(email: Email): Promise<User | null>;
  save(user: User): Promise<User>;
  existsByEmail(email: Email): Promise<boolean>;
}

export const IUserRepository = Symbol('IUserRepository');
```

**File: `src/domain/repositories/index.ts`**
```typescript
export * from './user.repository.interface';
```

---

#### 1.4 Domain Exceptions

**File: `src/domain/exceptions/domain.exception.ts`**
```typescript
export abstract class DomainException extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}
```

**File: `src/domain/exceptions/user-already-exists.exception.ts`**
```typescript
import { DomainException } from './domain.exception';

export class UserAlreadyExistsException extends DomainException {
  constructor(email?: string) {
    super(
      email ? `User with email ${email} already exists` : 'User already exists',
      'USER_ALREADY_EXISTS',
    );
  }
}
```

**File: `src/domain/exceptions/index.ts`**
```typescript
export * from './domain.exception';
export * from './user-already-exists.exception';
```

---

#### 1.5 Domain Root Export

**File: `src/domain/index.ts`**
```typescript
export * from './entities';
export * from './value-objects';
export * from './repositories';
export * from './exceptions';
```

---

### Phase 2: Configuration Extension

#### 2.1 Update Application Ports
**File:** `src/application/ports/config.interface.ts`

Add `DatabaseConfig` interface and update `IAppConfig`:
```typescript
export interface DatabaseConfig {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly username: string;
  readonly password: string;
}

export interface IAppConfig {
  readonly appConfig: AppConfig;
  readonly logger: LoggerConfig;
  readonly database: DatabaseConfig; // ADD THIS
}
```

---

#### 2.2 Update Config Service
**File:** `src/infrastructure/config/config.ts`

Add `database` getter to `AppConfigService`:
```typescript
get database(): DatabaseConfig {
  return {
    host: this.configService.get<string>('POSTGRES_HOST', 'localhost'),
    port: this.configService.get<number>('POSTGRES_PORT', 5432),
    database: this.configService.get<string>('POSTGRES_DB', 'db'),
    username: this.configService.get<string>('POSTGRES_USER', 'db'),
    password: this.configService.get<string>('POSTGRES_PASSWORD', 'db'),
  };
}
```

---

### Phase 3: Application Ports

#### 3.1 Password Hasher Interface

**File: `src/application/ports/password-hasher.interface.ts`**
```typescript
export interface IPasswordHasher {
  hash(password: string): Promise<string>;
  compare(password: string, hash: string): Promise<boolean>;
}

export const IPasswordHasher = Symbol('IPasswordHasher');
```

#### 3.2 Update Ports Index

**File: `src/application/ports/index.ts`**
```typescript
export * from './config.interface';
export * from './logger.interface';
export * from './password-hasher.interface';
```

---

### Phase 4: Application Layer

#### 4.1 DTOs

**File: `src/application/dtos/register-user.dto.ts`**
```typescript
import { IsEmail, IsNotEmpty, IsString, MinLength, Matches } from 'class-validator';

export class RegisterUserDto {
  @IsEmail({}, { message: 'Invalid email format' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @Matches(/[A-Z]/, { message: 'Password must contain at least one uppercase letter' })
  @Matches(/[a-z]/, { message: 'Password must contain at least one lowercase letter' })
  @Matches(/[0-9]/, { message: 'Password must contain at least one number' })
  password: string;
}
```

**File: `src/application/dtos/user-response.dto.ts`**
```typescript
export class UserResponseDto {
  id: string;
  email: string;
  createdAt: Date;
  updatedAt: Date;

  static fromDomain(user: any): UserResponseDto {
    return {
      id: user.id.toString(),
      email: user.email.toString(),
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
```

**File: `src/application/dtos/index.ts`**
```typescript
export * from './register-user.dto';
export * from './user-response.dto';
```

---

#### 4.2 Use Case

**File: `src/application/use-cases/register-user.use-case.ts`**
```typescript
import { Inject, Injectable, ConflictException } from '@nestjs/common';
import { IUserRepository } from '@domain/repositories';
import { IPasswordHasher } from '@application/ports';
import { Email, Password, User } from '@domain';
import { UserAlreadyExistsException } from '@domain/exceptions';
import { ILogger } from '@application/ports';
import { RegisterUserDto } from '../dtos';

@Injectable()
export class RegisterUserUseCase {
  constructor(
    @Inject(IUserRepository)
    private readonly userRepository: IUserRepository,
    @Inject(IPasswordHasher)
    private readonly passwordHasher: IPasswordHasher,
    @Inject(ILogger)
    private readonly logger: ILogger,
  ) {}

  async execute(dto: RegisterUserDto): Promise<User> {
    // 1. Create value objects (validates format)
    const email = Email.create(dto.email);
    Password.create(dto.password); // Validate password format

    // 2. Check if user already exists
    const existingUser = await this.userRepository.findByEmail(email);
    if (existingUser) {
      this.logger.warn(
        'User registration failed: email already exists',
        'RegisterUserUseCase',
        { email: dto.email, action: 'REGISTER_FAILED', reason: 'DUPLICATE_EMAIL' },
      );
      throw new ConflictException('User with this email already exists');
    }

    // 3. Hash password
    const passwordHash = await this.passwordHasher.hash(dto.password);

    // 4. Create domain entity
    const user = User.create(email, passwordHash);

    // 5. Persist user
    const savedUser = await this.userRepository.save(user);

    // 6. Log success
    this.logger.info('User registered successfully', 'RegisterUserUseCase', {
      userId: savedUser.id.toString(),
      email: savedUser.email.toString(),
      action: 'REGISTER_SUCCESS',
    });

    return savedUser;
  }
}
```

**File: `src/application/use-cases/index.ts`**
```typescript
export * from './register-user.use-case';
```

---

### Phase 5: Infrastructure - Persistence

#### 5.1 TypeORM Entity

**File: `src/infrastructure/persistence/entities/user.typeorm-entity.ts`**
```typescript
import { Entity, Column, PrimaryColumn, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('users')
export class UserEntity {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ name: 'password_hash' })
  passwordHash: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
```

**File: `src/infrastructure/persistence/entities/index.ts`**
```typescript
export * from './user.typeorm-entity';
```

---

#### 5.2 Repository Implementation

**File: `src/infrastructure/persistence/repositories/typeorm-user.repository.ts`**
```typescript
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { IUserRepository } from '@domain/repositories';
import { User } from '@domain/entities';
import { Email, UserId } from '@domain/value-objects';
import { UserEntity } from '../entities/user.typeorm-entity';

@Injectable()
export class TypeOrmUserRepository implements IUserRepository {
  constructor(
    @InjectRepository(UserEntity)
    private readonly repository: Repository<UserEntity>,
  ) {}

  async findById(id: UserId): Promise<User | null> {
    const entity = await this.repository.findOne({ where: { id: id.toString() } });
    return entity ? this.toDomain(entity) : null;
  }

  async findByEmail(email: Email): Promise<User | null> {
    const entity = await this.repository.findOne({ where: { email: email.toString() } });
    return entity ? this.toDomain(entity) : null;
  }

  async save(user: User): Promise<User> {
    const entity = this.toEntity(user);
    const saved = await this.repository.save(entity);
    return this.toDomain(saved);
  }

  async existsByEmail(email: Email): Promise<boolean> {
    const count = await this.repository.count({ where: { email: email.toString() } });
    return count > 0;
  }

  private toDomain(entity: UserEntity): User {
    return User.reconstitute({
      id: UserId.fromString(entity.id),
      email: Email.create(entity.email),
      passwordHash: entity.passwordHash,
      createdAt: entity.createdAt,
      updatedAt: entity.updatedAt,
    });
  }

  private toEntity(user: User): UserEntity {
    const entity = new UserEntity();
    entity.id = user.id.toString();
    entity.email = user.email.toString();
    entity.passwordHash = user.passwordHash;
    entity.createdAt = user.createdAt;
    entity.updatedAt = user.updatedAt;
    return entity;
  }
}
```

**File: `src/infrastructure/persistence/repositories/index.ts`**
```typescript
export * from './typeorm-user.repository';
```

---

#### 5.3 Persistence Module

**File: `src/infrastructure/persistence/persistence.module.ts`**
```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { IAppConfig } from '@application/ports';
import { AppConfigModule } from '../config/server-config.module';
import { UserEntity } from './entities/user.typeorm-entity';
import { TypeOrmUserRepository } from './repositories/typeorm-user.repository';
import { IUserRepository } from '@domain/repositories';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [AppConfigModule],
      inject: [IAppConfig],
      useFactory: (config: IAppConfig) => ({
        type: 'postgres',
        host: config.database.host,
        port: config.database.port,
        username: config.database.username,
        password: config.database.password,
        database: config.database.database,
        entities: [UserEntity],
        synchronize: true, // Set to false in production, use migrations
        logging: config.appConfig.nodeEnv === 'development',
      }),
    }),
    TypeOrmModule.forFeature([UserEntity]),
  ],
  providers: [
    {
      provide: IUserRepository,
      useClass: TypeOrmUserRepository,
    },
  ],
  exports: [IUserRepository],
})
export class PersistenceModule {}
```

**File: `src/infrastructure/persistence/index.ts`**
```typescript
export * from './persistence.module';
export * from './entities';
export * from './repositories';
```

---

### Phase 6: Infrastructure - Security

#### 6.1 Password Hasher Implementation

**File: `src/infrastructure/security/bcrypt-password-hasher.ts`**
```typescript
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { IPasswordHasher } from '@application/ports';

@Injectable()
export class BcryptPasswordHasher implements IPasswordHasher {
  private readonly saltRounds = 10;

  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async compare(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}
```

---

#### 6.2 Security Module

**File: `src/infrastructure/security/security.module.ts`**
```typescript
import { Module } from '@nestjs/common';
import { IPasswordHasher } from '@application/ports';
import { BcryptPasswordHasher } from './bcrypt-password-hasher';

@Module({
  providers: [
    {
      provide: IPasswordHasher,
      useClass: BcryptPasswordHasher,
    },
  ],
  exports: [IPasswordHasher],
})
export class SecurityModule {}
```

**File: `src/infrastructure/security/index.ts`**
```typescript
export * from './security.module';
export * from './bcrypt-password-hasher';
```

---

### Phase 7: Interface Layer - HTTP

#### 7.1 Update Auth Controller

**File: `src/interfaces/http/controllers/auth.controller.ts`**
```typescript
import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { RegisterUserUseCase } from '@application/use-cases';
import { RegisterUserDto, UserResponseDto } from '@application/dtos';

@Controller('auth')
export class AuthController {
  constructor(private readonly registerUserUseCase: RegisterUserUseCase) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterUserDto): Promise<UserResponseDto> {
    const user = await this.registerUserUseCase.execute(dto);
    return UserResponseDto.fromDomain(user);
  }
}
```

---

#### 7.2 Update Auth Module

**File: `src/interfaces/http/auth.module.ts`**
```typescript
import { Module } from '@nestjs/common';
import { AuthController } from './controllers/auth.controller';
import { RegisterUserUseCase } from '@application/use-cases';
import { PersistenceModule } from '@infrastructure/persistence';
import { SecurityModule } from '@infrastructure/security';
import { LoggerModule } from '@infrastructure/logging';

@Module({
  imports: [PersistenceModule, SecurityModule, LoggerModule],
  controllers: [AuthController],
  providers: [RegisterUserUseCase],
})
export class AuthModule {}
```

---

### Phase 8: Enable Global Validation

#### 8.1 Update Main Bootstrap

**File: `src/main.ts`**
```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { IAppConfig } from '@application/ports';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  const config = app.get<IAppConfig>(IAppConfig);
  
  // Enable validation globally
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  await app.listen(config.appConfig.port, config.appConfig.host);
  console.log(`🚀 Application running on http://${config.appConfig.host}:${config.appConfig.port}`);
}
bootstrap();
```

---

## Testing Strategy

### Unit Tests
1. **Domain Layer:**
   - `email.vo.spec.ts` - Email validation
   - `password.vo.spec.ts` - Password rules
   - `user.entity.spec.ts` - Entity creation

2. **Application Layer:**
   - `register-user.use-case.spec.ts` - Business logic with mocks

3. **Infrastructure Layer:**
   - `bcrypt-password-hasher.spec.ts` - Hashing functionality
   - `typeorm-user.repository.spec.ts` - Repository with test DB

### Integration Tests
- Test `RegisterUserUseCase` with real database (test container)

### E2E Tests
- `POST /auth/register` with valid data → 201 Created
- `POST /auth/register` with duplicate email → 409 Conflict
- `POST /auth/register` with invalid email → 400 Bad Request
- `POST /auth/register` with weak password → 400 Bad Request

---

## API Specification

### Endpoint: `POST /auth/register`

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Success Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "createdAt": "2026-01-28T10:30:00.000Z",
  "updatedAt": "2026-01-28T10:30:00.000Z"
}
```

**Error Responses:**

**409 Conflict (User exists):**
```json
{
  "statusCode": 409,
  "message": "User with this email already exists",
  "error": "Conflict",
  "correlationId": "abc-123-def-456"
}
```

**400 Bad Request (Validation failed):**
```json
{
  "statusCode": 400,
  "message": [
    "Invalid email format",
    "Password must be at least 8 characters",
    "Password must contain at least one uppercase letter"
  ],
  "error": "Bad Request",
  "correlationId": "abc-123-def-456"
}
```

---

## Security Considerations

### Password Storage
- ✅ Bcrypt hashing with 10 salt rounds
- ✅ Plain passwords never stored
- ✅ Passwords sanitized in logs (via WinstonLoggerService PII filtering)

### Input Validation
- ✅ Email format validation (DTO + Value Object)
- ✅ Password complexity requirements (DTO + Value Object)
- ✅ Whitelist validation (forbid unknown properties)

### Logging & Audit Trail
- ✅ Log registration success with userId and email
- ✅ Log registration failures (duplicate email)
- ✅ Correlation IDs for request tracing
- ✅ PII sanitization automatic

---

## Database Schema

### Table: `users`

| Column | Type | Constraints |
|--------|------|-------------|
| id | UUID | PRIMARY KEY |
| email | VARCHAR | UNIQUE, NOT NULL |
| password_hash | VARCHAR | NOT NULL |
| created_at | TIMESTAMP | NOT NULL, DEFAULT NOW() |
| updated_at | TIMESTAMP | NOT NULL, DEFAULT NOW() |

**Indexes:**
- Primary key on `id`
- Unique index on `email`

---

## Environment Variables

Add to `.env`:
```bash
# Database (already exists, verify values)
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=db
POSTGRES_USER=db
POSTGRES_PASSWORD=db
```

---

## Logging Integration

### Auth Events to Log

Based on `PRODUCTION_LOGGING_PLAN.md` Phase 5:

**Registration Success:**
```typescript
this.logger.info('User registered successfully', 'RegisterUserUseCase', {
  userId: user.id.toString(),
  email: user.email.toString(),
  action: 'REGISTER_SUCCESS',
});
```

**Registration Failed (Duplicate):**
```typescript
this.logger.warn('User registration failed: email already exists', 'RegisterUserUseCase', {
  email: dto.email,
  action: 'REGISTER_FAILED',
  reason: 'DUPLICATE_EMAIL',
});
```

---

## File Structure Summary

```
src/
├── domain/                          # NEW - Pure TypeScript
│   ├── entities/
│   │   ├── user.entity.ts
│   │   └── index.ts
│   ├── value-objects/
│   │   ├── user-id.vo.ts
│   │   ├── email.vo.ts
│   │   ├── password.vo.ts
│   │   └── index.ts
│   ├── repositories/
│   │   ├── user.repository.interface.ts
│   │   └── index.ts
│   ├── exceptions/
│   │   ├── domain.exception.ts
│   │   ├── user-already-exists.exception.ts
│   │   └── index.ts
│   └── index.ts
│
├── application/
│   ├── dtos/                        # NEW
│   │   ├── register-user.dto.ts
│   │   ├── user-response.dto.ts
│   │   └── index.ts
│   ├── use-cases/                   # NEW
│   │   ├── register-user.use-case.ts
│   │   └── index.ts
│   └── ports/
│       ├── config.interface.ts      # MODIFIED - Add DatabaseConfig
│       ├── password-hasher.interface.ts  # NEW
│       └── index.ts                 # MODIFIED
│
├── infrastructure/
│   ├── config/
│   │   └── config.ts                # MODIFIED - Add database getter
│   ├── persistence/                 # NEW
│   │   ├── entities/
│   │   │   ├── user.typeorm-entity.ts
│   │   │   └── index.ts
│   │   ├── repositories/
│   │   │   ├── typeorm-user.repository.ts
│   │   │   └── index.ts
│   │   ├── persistence.module.ts
│   │   └── index.ts
│   └── security/                    # NEW
│       ├── bcrypt-password-hasher.ts
│       ├── security.module.ts
│       └── index.ts
│
├── interfaces/
│   └── http/
│       ├── controllers/
│       │   └── auth.controller.ts   # MODIFIED - Add register endpoint
│       └── auth.module.ts           # MODIFIED - Wire dependencies
│
└── main.ts                          # MODIFIED - Add ValidationPipe
```

---

## Next Steps After Registration

1. **Login Endpoint** - JWT token generation with RS256
2. **Refresh Token Endpoint** - Token rotation
3. **Get User Profile** - JWT authentication guard
4. **Logout Endpoint** - Token revocation

---

## References

- [CHECKLIST.md](CHECKLIST.md) - Project roadmap
- `.copilot-instructions.md` - Clean Architecture guidelines
- [docker-postgres.yml](docker-postgres.yml) - Database setup

---

**Plan Created:** January 28, 2026  
**Status:** ✅ Ready for Implementation  
**Estimated Effort:** 4-6 hours
