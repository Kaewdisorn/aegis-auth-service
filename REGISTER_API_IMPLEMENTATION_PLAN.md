# Register API Implementation Plan
## Aegis Auth Service

**Date:** January 28, 2026  
**Updated:** February 9, 2026  
**Status:** In Progress  
**Goal:** Implement user registration endpoint with Clean Architecture

---

## Overview

Build a complete user registration flow following Clean Architecture principles:
- **Domain Layer:** Pure TypeScript entities, value objects, repository interfaces
- **Application Layer:** Use cases, DTOs with validation
- **Infrastructure Layer:** TypeORM persistence, bcrypt password hashing
- **Interface Layer:** HTTP POST endpoint at `/auth/register`

---

## Current State Assessment

### What Already Exists (✅ Done)

| File | Status | Notes |
|------|--------|-------|
| `src/domain/value-objects/email.vo.ts` | ✅ Complete | Matches plan exactly |
| `src/domain/value-objects/password.vo.ts` | ⚠️ Partial | Missing `fromHash()` method and `toString()` returning `[REDACTED]` |
| `src/domain/entities/user.entity.ts` | ❌ Empty | File exists but has no content |
| `src/application/dtos/register-user.dto.ts` | ⚠️ Partial | Missing `@Matches` validators for uppercase/lowercase/number |
| `src/application/use-cases/register-user.use-case.ts` | ⚠️ Partial | Stub only — no DI, no repository/hasher/logger, has console.log |
| `src/application/ports/config.interface.ts` | ⚠️ Needs update | Missing `DatabaseConfig` |
| `src/application/ports/logger.interface.ts` | ✅ Complete | Full ILogger with metadata interfaces |
| `src/infrastructure/config/config.ts` | ⚠️ Needs update | Missing `database` getter |
| `src/infrastructure/config/server-config.module.ts` | ✅ Complete | AppConfigModule with IAppConfig provider |
| `src/infrastructure/logging/winston-logger.service.ts` | ✅ Complete | Full WinstonLoggerService with PII filtering |
| `src/infrastructure/logging/logger.module.ts` | ✅ Complete | LoggerModule exporting ILogger |
| `src/infrastructure/filters/global-exception.filter.ts` | ✅ Complete | Global exception handling |
| `src/infrastructure/filters/http-exception.filter.ts` | ✅ Complete | HTTP exception handling |
| `src/infrastructure/middleware/correlation-id.middleware.ts` | ✅ Complete | Correlation ID middleware |
| `src/infrastructure/middleware/http-logger.middleware.ts` | ✅ Complete | HTTP logging middleware |
| `src/interfaces/http/controllers/auth.controller.ts` | ⚠️ Needs update | Route is `@Post('/')` instead of `@Post('register')`, no response DTO, no HttpCode |
| `src/interfaces/http/auth.module.ts` | ⚠️ Needs update | Missing PersistenceModule, SecurityModule, LoggerModule imports |
| `src/app.module.ts` | ✅ Complete | Middleware configured, modules wired |
| `src/main.ts` | ✅ Complete | ValidationPipe + GlobalFilters already configured |
| `package.json` | ⚠️ Partial | Has `@nestjs/typeorm`, `typeorm`, `pg`, `class-validator`, `class-transformer`. Missing `bcrypt`, `@types/bcrypt` |
| `tsconfig.json` | ✅ Complete | Path aliases for `@application`, `@infrastructure`, `@domain`, `@interfaces` |

### What Needs to Be Created (❌ Missing)

| File | Phase |
|------|-------|
| `src/domain/value-objects/user-id.vo.ts` | Phase 1.1 |
| `src/domain/value-objects/index.ts` | Phase 1.1 |
| `src/domain/entities/index.ts` | Phase 1.2 |
| `src/domain/repositories/user.repository.interface.ts` | Phase 1.3 |
| `src/domain/repositories/index.ts` | Phase 1.3 |
| `src/domain/exceptions/domain.exception.ts` | Phase 1.4 |
| `src/domain/exceptions/user-already-exists.exception.ts` | Phase 1.4 |
| `src/domain/exceptions/index.ts` | Phase 1.4 |
| `src/domain/index.ts` | Phase 1.5 |
| `src/application/ports/password-hasher.interface.ts` | Phase 3.1 |
| `src/application/dtos/user-response.dto.ts` | Phase 4.1 |
| `src/application/dtos/index.ts` | Phase 4.1 |
| `src/application/use-cases/index.ts` | Phase 4.2 |
| `src/application/ports/index.ts` | Phase 3.2 |
| `src/infrastructure/persistence/entities/user.typeorm-entity.ts` | Phase 5.1 |
| `src/infrastructure/persistence/entities/index.ts` | Phase 5.1 |
| `src/infrastructure/persistence/repositories/typeorm-user.repository.ts` | Phase 5.2 |
| `src/infrastructure/persistence/repositories/index.ts` | Phase 5.2 |
| `src/infrastructure/persistence/persistence.module.ts` | Phase 5.3 |
| `src/infrastructure/persistence/index.ts` | Phase 5.3 |
| `src/infrastructure/security/bcrypt-password-hasher.ts` | Phase 6.1 |
| `src/infrastructure/security/security.module.ts` | Phase 6.2 |
| `src/infrastructure/security/index.ts` | Phase 6.2 |

---

## Prerequisites

### Install Dependencies
```bash
npm install bcrypt
npm install --save-dev @types/bcrypt
```

> **Already installed:** `@nestjs/typeorm`, `typeorm`, `pg`, `class-validator`, `class-transformer`, `uuid`
> **Not needed:** `@nestjs/jwt` (for login phase, not registration)

---

## Implementation Steps

### Phase 1: Domain Layer (Pure TypeScript - Zero Dependencies)

#### 1.1 Value Objects

**CREATE File: `src/domain/value-objects/user-id.vo.ts`**
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

**UPDATE File: `src/domain/value-objects/password.vo.ts`** — Add missing `fromHash()` and `toString()`:
```typescript
  /**
   * Creates a Password value object from an already-hashed password (from DB)
   */
  static fromHash(hashedPassword: string): Password {
    if (!hashedPassword || hashedPassword.trim().length === 0) {
      throw new Error('Hashed password cannot be empty');
    }
    return new Password(hashedPassword);
  }

  // ... existing validate() ...

  toString(): string {
    return '[REDACTED]';
  }
```

**File: `src/domain/value-objects/email.vo.ts`** — ✅ No changes needed

**CREATE File: `src/domain/value-objects/index.ts`**
```typescript
export * from './user-id.vo';
export * from './email.vo';
export * from './password.vo';
```

---

#### 1.2 Domain Entities

**WRITE File: `src/domain/entities/user.entity.ts`** (currently empty)
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

  static reconstitute(props: UserProps): User {
    return new User(props);
  }

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

**CREATE File: `src/domain/entities/index.ts`**
```typescript
export * from './user.entity';
```

---

#### 1.3 Repository Interfaces

**CREATE File: `src/domain/repositories/user.repository.interface.ts`**
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

**CREATE File: `src/domain/repositories/index.ts`**
```typescript
export * from './user.repository.interface';
```

---

#### 1.4 Domain Exceptions

**CREATE File: `src/domain/exceptions/domain.exception.ts`**
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

**CREATE File: `src/domain/exceptions/user-already-exists.exception.ts`**
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

**CREATE File: `src/domain/exceptions/index.ts`**
```typescript
export * from './domain.exception';
export * from './user-already-exists.exception';
```

---

#### 1.5 Domain Root Export

**CREATE File: `src/domain/index.ts`**
```typescript
export * from './entities';
export * from './value-objects';
export * from './repositories';
export * from './exceptions';
```

---

### Phase 2: Configuration Extension

#### 2.1 Update Application Ports
**UPDATE File:** `src/application/ports/config.interface.ts`

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
**UPDATE File:** `src/infrastructure/config/config.ts`

Add `database` property to `AppConfigService` constructor:
```typescript
public readonly database: DatabaseConfig;

// Inside constructor, add:
this.database = {
  host: this.configService.get<string>('POSTGRES_HOST', 'localhost'),
  port: this.configService.get<number>('POSTGRES_PORT', 5432),
  database: this.configService.get<string>('POSTGRES_DB', 'db'),
  username: this.configService.get<string>('POSTGRES_USER', 'db'),
  password: this.configService.get<string>('POSTGRES_PASSWORD', 'db'),
};
```

---

### Phase 3: Application Ports

#### 3.1 Password Hasher Interface

**CREATE File: `src/application/ports/password-hasher.interface.ts`**
```typescript
export interface IPasswordHasher {
  hash(password: string): Promise<string>;
  compare(password: string, hash: string): Promise<boolean>;
}

export const IPasswordHasher = Symbol('IPasswordHasher');
```

#### 3.2 Create Ports Index

**CREATE File: `src/application/ports/index.ts`**
```typescript
export * from './config.interface';
export * from './logger.interface';
export * from './password-hasher.interface';
```

---

### Phase 4: Application Layer

#### 4.1 DTOs

**UPDATE File: `src/application/dtos/register-user.dto.ts`** — Add `@Matches` validators:
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

**CREATE File: `src/application/dtos/user-response.dto.ts`**
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

**CREATE File: `src/application/dtos/index.ts`**
```typescript
export * from './register-user.dto';
export * from './user-response.dto';
```

---

#### 4.2 Use Case

**REWRITE File: `src/application/use-cases/register-user.use-case.ts`** — Current is a stub with console.log, needs full implementation:
```typescript
import { Inject, Injectable, ConflictException } from '@nestjs/common';
import { IUserRepository } from '@domain/repositories';
import { IPasswordHasher } from '@application/ports';
import { Email, Password } from '@domain/value-objects';
import { User } from '@domain/entities';
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

**CREATE File: `src/application/use-cases/index.ts`**
```typescript
export * from './register-user.use-case';
```

---

### Phase 5: Infrastructure - Persistence

#### 5.1 TypeORM Entity

**CREATE File: `src/infrastructure/persistence/entities/user.typeorm-entity.ts`**
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

**CREATE File: `src/infrastructure/persistence/entities/index.ts`**
```typescript
export * from './user.typeorm-entity';
```

---

#### 5.2 Repository Implementation

**CREATE File: `src/infrastructure/persistence/repositories/typeorm-user.repository.ts`**
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

**CREATE File: `src/infrastructure/persistence/repositories/index.ts`**
```typescript
export * from './typeorm-user.repository';
```

---

#### 5.3 Persistence Module

**CREATE File: `src/infrastructure/persistence/persistence.module.ts`**
```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
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

**CREATE File: `src/infrastructure/persistence/index.ts`**
```typescript
export * from './persistence.module';
export * from './entities';
export * from './repositories';
```

---

### Phase 6: Infrastructure - Security

#### 6.1 Password Hasher Implementation

**CREATE File: `src/infrastructure/security/bcrypt-password-hasher.ts`**
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

**CREATE File: `src/infrastructure/security/security.module.ts`**
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

**CREATE File: `src/infrastructure/security/index.ts`**
```typescript
export * from './security.module';
export * from './bcrypt-password-hasher';
```

---

### Phase 7: Interface Layer - HTTP

#### 7.1 Update Auth Controller

**UPDATE File: `src/interfaces/http/controllers/auth.controller.ts`** — Change route from `@Post('/')` to `@Post('register')`, add `HttpCode`, use `UserResponseDto`:
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

**UPDATE File: `src/interfaces/http/auth.module.ts`** — Add PersistenceModule, SecurityModule, LoggerModule imports:
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

**`src/main.ts`** — ✅ No changes needed. ValidationPipe already configured with `whitelist`, `forbidNonWhitelisted`, `transform`.

**`src/app.module.ts`** — ✅ No changes needed. PersistenceModule will be imported via AuthModule.

---

## Implementation Summary

### Files to CREATE (23 new files):
1. `src/domain/value-objects/user-id.vo.ts`
2. `src/domain/value-objects/index.ts`
3. `src/domain/entities/index.ts`
4. `src/domain/repositories/user.repository.interface.ts`
5. `src/domain/repositories/index.ts`
6. `src/domain/exceptions/domain.exception.ts`
7. `src/domain/exceptions/user-already-exists.exception.ts`
8. `src/domain/exceptions/index.ts`
9. `src/domain/index.ts`
10. `src/application/ports/password-hasher.interface.ts`
11. `src/application/ports/index.ts`
12. `src/application/dtos/user-response.dto.ts`
13. `src/application/dtos/index.ts`
14. `src/application/use-cases/index.ts`
15. `src/infrastructure/persistence/entities/user.typeorm-entity.ts`
16. `src/infrastructure/persistence/entities/index.ts`
17. `src/infrastructure/persistence/repositories/typeorm-user.repository.ts`
18. `src/infrastructure/persistence/repositories/index.ts`
19. `src/infrastructure/persistence/persistence.module.ts`
20. `src/infrastructure/persistence/index.ts`
21. `src/infrastructure/security/bcrypt-password-hasher.ts`
22. `src/infrastructure/security/security.module.ts`
23. `src/infrastructure/security/index.ts`

### Files to UPDATE (6 existing files):
1. `src/domain/value-objects/password.vo.ts` — Add `fromHash()` + `toString()`
2. `src/domain/entities/user.entity.ts` — Write full content (currently empty)
3. `src/application/ports/config.interface.ts` — Add `DatabaseConfig` + update `IAppConfig`
4. `src/infrastructure/config/config.ts` — Add `database` property
5. `src/application/dtos/register-user.dto.ts` — Add `@Matches` validators
6. `src/application/use-cases/register-user.use-case.ts` — Full rewrite (current is stub)
7. `src/interfaces/http/controllers/auth.controller.ts` — Route + response DTO + HttpCode
8. `src/interfaces/http/auth.module.ts` — Add module imports

### Files that need NO changes (already complete):
- `src/domain/value-objects/email.vo.ts`
- `src/application/ports/logger.interface.ts`
- `src/infrastructure/logging/winston-logger.service.ts`
- `src/infrastructure/logging/logger.module.ts`
- `src/infrastructure/config/server-config.module.ts`
- `src/infrastructure/filters/global-exception.filter.ts`
- `src/infrastructure/filters/http-exception.filter.ts`
- `src/infrastructure/middleware/correlation-id.middleware.ts`
- `src/infrastructure/middleware/http-logger.middleware.ts`
- `src/app.module.ts`
- `src/main.ts`
- `tsconfig.json`

### Dependencies to install:
```bash
npm install bcrypt
npm install --save-dev @types/bcrypt
```

---

## Testing Strategy

### Unit Tests
1. **Domain Layer:**
   - `email.vo.spec.ts` - Email validation
   - `password.vo.spec.ts` - Password rules
   - `user-id.vo.spec.ts` - UserId generation
   - `user.entity.spec.ts` - Entity creation

2. **Application Layer:**
   - `register-user.use-case.spec.ts` - Business logic with mocks

3. **Infrastructure Layer:**
   - `bcrypt-password-hasher.spec.ts` - Hashing functionality
   - `typeorm-user.repository.spec.ts` - Repository with test DB

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

## File Structure Summary

```
src/
├── domain/
│   ├── entities/
│   │   ├── user.entity.ts           # WRITE (currently empty)
│   │   └── index.ts                 # CREATE
│   ├── value-objects/
│   │   ├── user-id.vo.ts            # CREATE
│   │   ├── email.vo.ts              ✅ EXISTS - no changes
│   │   ├── password.vo.ts           # UPDATE - add fromHash() + toString()
│   │   └── index.ts                 # CREATE
│   ├── repositories/                # CREATE (entire directory)
│   │   ├── user.repository.interface.ts
│   │   └── index.ts
│   ├── exceptions/                  # CREATE (entire directory)
│   │   ├── domain.exception.ts
│   │   ├── user-already-exists.exception.ts
│   │   └── index.ts
│   └── index.ts                     # CREATE
│
├── application/
│   ├── dtos/
│   │   ├── register-user.dto.ts     # UPDATE - add @Matches validators
│   │   ├── user-response.dto.ts     # CREATE
│   │   └── index.ts                 # CREATE
│   ├── use-cases/
│   │   ├── register-user.use-case.ts # REWRITE (stub → full)
│   │   └── index.ts                 # CREATE
│   └── ports/
│       ├── config.interface.ts      # UPDATE - add DatabaseConfig
│       ├── logger.interface.ts      ✅ EXISTS - no changes
│       ├── password-hasher.interface.ts  # CREATE
│       └── index.ts                 # CREATE
│
├── infrastructure/
│   ├── config/
│   │   ├── config.ts                # UPDATE - add database property
│   │   └── server-config.module.ts  ✅ EXISTS - no changes
│   ├── logging/                     ✅ EXISTS - no changes
│   ├── filters/                     ✅ EXISTS - no changes
│   ├── middleware/                   ✅ EXISTS - no changes
│   ├── persistence/                 # CREATE (entire directory)
│   │   ├── entities/
│   │   │   ├── user.typeorm-entity.ts
│   │   │   └── index.ts
│   │   ├── repositories/
│   │   │   ├── typeorm-user.repository.ts
│   │   │   └── index.ts
│   │   ├── persistence.module.ts
│   │   └── index.ts
│   └── security/                    # CREATE (entire directory)
│       ├── bcrypt-password-hasher.ts
│       ├── security.module.ts
│       └── index.ts
│
├── interfaces/
│   └── http/
│       ├── controllers/
│       │   └── auth.controller.ts   # UPDATE - route + response DTO
│       └── auth.module.ts           # UPDATE - add module imports
│
├── app.module.ts                    ✅ EXISTS - no changes
└── main.ts                          ✅ EXISTS - no changes
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
**Updated:** February 9, 2026  
**Status:** 🔄 In Progress  
**Estimated Remaining Effort:** 2-3 hours (foundation already built)
