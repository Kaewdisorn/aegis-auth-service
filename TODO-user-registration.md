# User Registration - Implementation Checklist

---

## 1. Install Dependencies

- [ ] Install TypeORM & database driver

```bash
npm install @nestjs/typeorm typeorm pg
```

- [ ] Install validation packages

```bash
npm install class-validator class-transformer
```

- [ ] Install password hashing library

```bash
npm install bcrypt
npm install -D @types/bcrypt
```

- [ ] Install configuration module

```bash
npm install @nestjs/config
```

---

## 2. Domain Layer (`src/modules/user/domain/`)

- [ ] Create User entity — `src/modules/user/domain/user.entity.ts`

```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ name: 'first_name' })
  firstName: string;

  @Column({ name: 'last_name' })
  lastName: string;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
```

- [ ] Create UserRepository interface (port) — `src/modules/user/domain/user-repository.interface.ts`

```typescript
import { User } from './user.entity.js';

export const USER_REPOSITORY = Symbol('USER_REPOSITORY');

export interface IUserRepository {
  findByEmail(email: string): Promise<User | null>;
  save(user: Partial<User>): Promise<User>;
}
```

- [ ] Create domain exception — `src/modules/user/domain/exceptions/user-already-exists.exception.ts`

```typescript
import { ConflictException } from '@nestjs/common';

export class UserAlreadyExistsException extends ConflictException {
  constructor(email: string) {
    super(`User with email "${email}" already exists`);
  }
}
```

---

## 3. Application Layer (`src/modules/user/application/`)

- [ ] Create RegisterUserDto — `src/modules/user/application/dto/register-user.dto.ts`

```typescript
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RegisterUserDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;
}
```

- [ ] Create UserResponseDto — `src/modules/user/application/dto/user-response.dto.ts`

```typescript
import { User } from '../../domain/user.entity.js';

export class UserResponseDto {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  isActive: boolean;
  createdAt: Date;

  static fromEntity(user: User): UserResponseDto {
    const dto = new UserResponseDto();
    dto.id = user.id;
    dto.email = user.email;
    dto.firstName = user.firstName;
    dto.lastName = user.lastName;
    dto.isActive = user.isActive;
    dto.createdAt = user.createdAt;
    return dto;
  }
}
```

- [ ] Create RegisterUserUseCase — `src/modules/user/application/use-cases/register-user.use-case.ts`

```typescript
import { Inject, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {
  IUserRepository,
  USER_REPOSITORY,
} from '../../domain/user-repository.interface.js';
import { UserAlreadyExistsException } from '../../domain/exceptions/user-already-exists.exception.js';
import { RegisterUserDto } from '../dto/register-user.dto.js';
import { UserResponseDto } from '../dto/user-response.dto.js';

@Injectable()
export class RegisterUserUseCase {
  constructor(
    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
  ) {}

  async execute(dto: RegisterUserDto): Promise<UserResponseDto> {
    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new UserAlreadyExistsException(dto.email);
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.userRepository.save({
      email: dto.email,
      password: hashedPassword,
      firstName: dto.firstName,
      lastName: dto.lastName,
    });

    return UserResponseDto.fromEntity(user);
  }
}
```

---

## 4. Infrastructure Layer (`src/modules/user/infrastructure/`)

- [ ] Create TypeOrmUserRepository — `src/modules/user/infrastructure/typeorm-user.repository.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../domain/user.entity.js';
import { IUserRepository } from '../domain/user-repository.interface.js';

@Injectable()
export class TypeOrmUserRepository implements IUserRepository {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email } });
  }

  async save(user: Partial<User>): Promise<User> {
    const newUser = this.userRepo.create(user);
    return this.userRepo.save(newUser);
  }
}
```

---

## 5. Presentation Layer (`src/modules/user/presentation/`)

- [ ] Create UserController — `src/modules/user/presentation/user.controller.ts`

```typescript
import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { RegisterUserUseCase } from '../application/use-cases/register-user.use-case.js';
import { RegisterUserDto } from '../application/dto/register-user.dto.js';
import { UserResponseDto } from '../application/dto/user-response.dto.js';

@Controller('users')
export class UserController {
  constructor(private readonly registerUserUseCase: RegisterUserUseCase) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() dto: RegisterUserDto): Promise<UserResponseDto> {
    return this.registerUserUseCase.execute(dto);
  }
}
```

---

## 6. Module Wiring

- [ ] Wire up `UserModule` — `src/modules/user/user.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './domain/user.entity.js';
import { USER_REPOSITORY } from './domain/user-repository.interface.js';
import { TypeOrmUserRepository } from './infrastructure/typeorm-user.repository.js';
import { RegisterUserUseCase } from './application/use-cases/register-user.use-case.js';
import { UserController } from './presentation/user.controller.js';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  controllers: [UserController],
  providers: [
    RegisterUserUseCase,
    {
      provide: USER_REPOSITORY,
      useClass: TypeOrmUserRepository,
    },
  ],
  exports: [USER_REPOSITORY],
})
export class UserModule {}
```

- [ ] Update `AppModule` — `src/app.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller.js';
import { AppService } from './app.service.js';
import { UserModule } from './modules/user/user.module.js';
import { User } from './modules/user/domain/user.entity.js';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        type: 'postgres',
        host: config.get<string>('DB_HOST', 'localhost'),
        port: config.get<number>('DB_PORT', 5432),
        username: config.get<string>('DB_USERNAME', 'postgres'),
        password: config.get<string>('DB_PASSWORD', 'postgres'),
        database: config.get<string>('DB_DATABASE', 'aegis_auth'),
        entities: [User],
        synchronize: config.get<string>('NODE_ENV') !== 'production',
      }),
    }),
    UserModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

- [ ] Add ValidationPipe globally — `src/main.ts`

```typescript
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
```

---

## 7. Configuration & Environment

- [ ] Create `.env` file (already in `.gitignore`)

```env
NODE_ENV=development

DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_DATABASE=aegis_auth
```

- [ ] Create `.env.example`

```env
NODE_ENV=development

DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=
DB_PASSWORD=
DB_DATABASE=aegis_auth
```

---

## 8. Testing

- [ ] Unit test: RegisterUserUseCase — `src/modules/user/application/use-cases/register-user.use-case.spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { RegisterUserUseCase } from './register-user.use-case.js';
import { USER_REPOSITORY } from '../../domain/user-repository.interface.js';
import { UserAlreadyExistsException } from '../../domain/exceptions/user-already-exists.exception.js';

describe('RegisterUserUseCase', () => {
  let useCase: RegisterUserUseCase;
  const mockUserRepository = {
    findByEmail: jest.fn(),
    save: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RegisterUserUseCase,
        { provide: USER_REPOSITORY, useValue: mockUserRepository },
      ],
    }).compile();

    useCase = module.get<RegisterUserUseCase>(RegisterUserUseCase);
    jest.clearAllMocks();
  });

  it('should register a new user successfully', async () => {
    const dto = {
      email: 'test@example.com',
      password: 'password123',
      firstName: 'John',
      lastName: 'Doe',
    };

    mockUserRepository.findByEmail.mockResolvedValue(null);
    mockUserRepository.save.mockResolvedValue({
      id: 'uuid-1',
      ...dto,
      password: 'hashed',
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const result = await useCase.execute(dto);

    expect(result.email).toBe(dto.email);
    expect(result).not.toHaveProperty('password');
    expect(mockUserRepository.findByEmail).toHaveBeenCalledWith(dto.email);
    expect(mockUserRepository.save).toHaveBeenCalled();
  });

  it('should throw UserAlreadyExistsException if email is taken', async () => {
    const dto = {
      email: 'taken@example.com',
      password: 'password123',
      firstName: 'Jane',
      lastName: 'Doe',
    };

    mockUserRepository.findByEmail.mockResolvedValue({ id: 'existing-id' });

    await expect(useCase.execute(dto)).rejects.toThrow(
      UserAlreadyExistsException,
    );
    expect(mockUserRepository.save).not.toHaveBeenCalled();
  });
});
```

- [ ] Unit test: UserController — `src/modules/user/presentation/user.controller.spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller.js';
import { RegisterUserUseCase } from '../application/use-cases/register-user.use-case.js';

describe('UserController', () => {
  let controller: UserController;
  const mockRegisterUserUseCase = { execute: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UserController],
      providers: [
        { provide: RegisterUserUseCase, useValue: mockRegisterUserUseCase },
      ],
    }).compile();

    controller = module.get<UserController>(UserController);
  });

  it('should call RegisterUserUseCase and return result', async () => {
    const dto = {
      email: 'test@example.com',
      password: 'password123',
      firstName: 'John',
      lastName: 'Doe',
    };
    const expected = { id: 'uuid-1', email: dto.email, firstName: 'John', lastName: 'Doe', isActive: true, createdAt: new Date() };

    mockRegisterUserUseCase.execute.mockResolvedValue(expected);

    const result = await controller.register(dto);
    expect(result).toEqual(expected);
    expect(mockRegisterUserUseCase.execute).toHaveBeenCalledWith(dto);
  });
});
```

- [ ] E2E test: Registration endpoint — `test/user-registration.e2e-spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module.js';

describe('User Registration (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('POST /users/register — should create a user (201)', () => {
    return request(app.getHttpServer())
      .post('/users/register')
      .send({
        email: 'new@example.com',
        password: 'securePass1',
        firstName: 'Alice',
        lastName: 'Smith',
      })
      .expect(201)
      .expect((res) => {
        expect(res.body.id).toBeDefined();
        expect(res.body.email).toBe('new@example.com');
        expect(res.body).not.toHaveProperty('password');
      });
  });

  it('POST /users/register — duplicate email (409)', async () => {
    const dto = {
      email: 'dup@example.com',
      password: 'securePass1',
      firstName: 'Bob',
      lastName: 'Dup',
    };
    await request(app.getHttpServer()).post('/users/register').send(dto);

    return request(app.getHttpServer())
      .post('/users/register')
      .send(dto)
      .expect(409);
  });

  it('POST /users/register — invalid email (400)', () => {
    return request(app.getHttpServer())
      .post('/users/register')
      .send({
        email: 'not-an-email',
        password: 'securePass1',
        firstName: 'Bad',
        lastName: 'Input',
      })
      .expect(400);
  });
});
```

---

## 9. Final Review

- [ ] Verify error responses are consistent (NestJS exception filters)
- [ ] Ensure no password leaks in any response DTO
- [ ] Confirm `ValidationPipe` rejects unknown fields (`forbidNonWhitelisted: true`)
- [ ] Check `synchronize: false` in production TypeORM config
- [ ] Consider rate limiting on `/users/register` endpoint
