# User Login (JWT Authentication) - Implementation Checklist

---

## 1. Install Dependencies

- [ ] Install JWT & Passport packages

```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt
npm install -D @types/passport-jwt
```

---

## 2. Environment Variables

- [ ] Add JWT config to `.env`

```env
JWT_SECRET=your-super-secret-key-change-in-production
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d
```

- [ ] Update `.env.example`

```env
JWT_SECRET=
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d
```

---

## 3. Domain Layer (`src/modules/auth/domain/`)

- [ ] Create RefreshToken entity — `src/modules/auth/domain/refresh-token.entity.ts`

```typescript
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../user/domain/user.entity';

@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column()
  tokenHash!: string;

  @Column({ type: 'uuid' })
  userUid!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userUid', referencedColumnName: 'uid' })
  user!: User;

  @Column({ type: 'timestamp' })
  expiresAt!: Date;

  @Column({ default: false })
  revoked!: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
```

- [ ] Create RefreshTokenRepository interface — `src/modules/auth/domain/refresh-token-repository.interface.ts`

```typescript
import { RefreshToken } from './refresh-token.entity';

export const REFRESH_TOKEN_REPOSITORY = Symbol('REFRESH_TOKEN_REPOSITORY');

export interface IRefreshTokenRepository {
  save(token: Partial<RefreshToken>): Promise<RefreshToken>;
  findByTokenHash(tokenHash: string): Promise<RefreshToken | null>;
  revokeByUserUid(userUid: string): Promise<void>;
  revokeByTokenHash(tokenHash: string): Promise<void>;
  deleteExpired(): Promise<void>;
}
```

- [ ] Create InvalidCredentialsException — `src/modules/auth/domain/exceptions/invalid-credentials.exception.ts`

```typescript
import { UnauthorizedException } from '@nestjs/common';

export class InvalidCredentialsException extends UnauthorizedException {
  constructor() {
    super('Invalid email or password');
  }
}
```

- [ ] Create InvalidRefreshTokenException — `src/modules/auth/domain/exceptions/invalid-refresh-token.exception.ts`

```typescript
import { UnauthorizedException } from '@nestjs/common';

export class InvalidRefreshTokenException extends UnauthorizedException {
  constructor() {
    super('Invalid or expired refresh token');
  }
}
```

---

## 4. Application Layer (`src/modules/auth/application/`)

- [ ] Create LoginDto — `src/modules/auth/application/dto/login.dto.ts`

```typescript
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @IsString()
  @MinLength(8)
  password!: string;
}
```

- [ ] Create AuthResponseDto — `src/modules/auth/application/dto/auth-response.dto.ts`

```typescript
export class AuthResponseDto {
  accessToken!: string;
  refreshToken!: string;
  expiresIn!: string;

  static create(
    accessToken: string,
    refreshToken: string,
    expiresIn: string,
  ): AuthResponseDto {
    const dto = new AuthResponseDto();
    dto.accessToken = accessToken;
    dto.refreshToken = refreshToken;
    dto.expiresIn = expiresIn;
    return dto;
  }
}
```

- [ ] Create RefreshTokenDto — `src/modules/auth/application/dto/refresh-token.dto.ts`

```typescript
import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshTokenDto {
  @IsString()
  @IsNotEmpty()
  refreshToken!: string;
}
```

- [ ] Create JwtPayload interface — `src/modules/auth/application/interfaces/jwt-payload.interface.ts`

```typescript
export interface JwtPayload {
  sub: string; // user uid
  gid: string;
  email: string;
}
```

- [ ] Create LoginUseCase — `src/modules/auth/application/use-cases/login.use-case.ts`

```typescript
import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { LoginDto } from '../dto/login.dto';
import { AuthResponseDto } from '../dto/auth-response.dto';
import {
  IUserRepository,
  USER_REPOSITORY,
} from '../../../modules/user/domain/user-repository.interface';
import {
  IRefreshTokenRepository,
  REFRESH_TOKEN_REPOSITORY,
} from '../../domain/refresh-token-repository.interface';
import { InvalidCredentialsException } from '../../domain/exceptions/invalid-credentials.exception';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class LoginUseCase {
  constructor(
    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
    @Inject(REFRESH_TOKEN_REPOSITORY)
    private readonly refreshTokenRepository: IRefreshTokenRepository,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async execute(dto: LoginDto): Promise<AuthResponseDto> {
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) {
      throw new InvalidCredentialsException();
    }

    const passwordValid = await bcrypt.compare(dto.password, user.password);
    if (!passwordValid) {
      throw new InvalidCredentialsException();
    }

    const payload: JwtPayload = {
      sub: user.uid,
      gid: user.gid,
      email: user.email,
    };

    const accessExpiration = this.configService.get<string>(
      'JWT_ACCESS_EXPIRATION',
      '15m',
    );

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: accessExpiration,
    });

    const refreshToken = crypto.randomBytes(64).toString('hex');
    const refreshTokenHash = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const refreshExpiration = this.configService.get<string>(
      'JWT_REFRESH_EXPIRATION',
      '7d',
    );
    const expiresAt = this.calculateExpiry(refreshExpiration);

    await this.refreshTokenRepository.save({
      tokenHash: refreshTokenHash,
      userUid: user.uid,
      expiresAt,
    });

    return AuthResponseDto.create(accessToken, refreshToken, accessExpiration);
  }

  private calculateExpiry(duration: string): Date {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) {
      return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // default 7d
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];
    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };

    return new Date(Date.now() + value * multipliers[unit]);
  }
}
```

- [ ] Create RefreshTokenUseCase — `src/modules/auth/application/use-cases/refresh-token.use-case.ts`

```typescript
import { Inject, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import { RefreshTokenDto } from '../dto/refresh-token.dto';
import { AuthResponseDto } from '../dto/auth-response.dto';
import {
  IUserRepository,
  USER_REPOSITORY,
} from '../../../modules/user/domain/user-repository.interface';
import {
  IRefreshTokenRepository,
  REFRESH_TOKEN_REPOSITORY,
} from '../../domain/refresh-token-repository.interface';
import { InvalidRefreshTokenException } from '../../domain/exceptions/invalid-refresh-token.exception';
import { JwtPayload } from '../interfaces/jwt-payload.interface';

@Injectable()
export class RefreshTokenUseCase {
  constructor(
    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
    @Inject(REFRESH_TOKEN_REPOSITORY)
    private readonly refreshTokenRepository: IRefreshTokenRepository,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async execute(dto: RefreshTokenDto): Promise<AuthResponseDto> {
    const tokenHash = crypto
      .createHash('sha256')
      .update(dto.refreshToken)
      .digest('hex');

    const storedToken =
      await this.refreshTokenRepository.findByTokenHash(tokenHash);

    if (!storedToken || storedToken.revoked || storedToken.expiresAt < new Date()) {
      throw new InvalidRefreshTokenException();
    }

    const user = await this.userRepository.findByEmail('');
    // We need findByUid — see step 5 below
    // For now, load user via the relation on the stored token
    // Better: add findByUid to IUserRepository

    const payload: JwtPayload = {
      sub: storedToken.userUid,
      gid: storedToken.user.gid,
      email: storedToken.user.email,
    };

    const accessExpiration = this.configService.get<string>(
      'JWT_ACCESS_EXPIRATION',
      '15m',
    );

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: accessExpiration,
    });

    // Rotate refresh token (revoke old, issue new)
    await this.refreshTokenRepository.revokeByTokenHash(tokenHash);

    const newRefreshToken = crypto.randomBytes(64).toString('hex');
    const newRefreshTokenHash = crypto
      .createHash('sha256')
      .update(newRefreshToken)
      .digest('hex');

    const refreshExpiration = this.configService.get<string>(
      'JWT_REFRESH_EXPIRATION',
      '7d',
    );
    const expiresAt = new Date(
      Date.now() + this.parseDurationMs(refreshExpiration),
    );

    await this.refreshTokenRepository.save({
      tokenHash: newRefreshTokenHash,
      userUid: storedToken.userUid,
      expiresAt,
    });

    return AuthResponseDto.create(
      accessToken,
      newRefreshToken,
      accessExpiration,
    );
  }

  private parseDurationMs(duration: string): number {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) return 7 * 24 * 60 * 60 * 1000;

    const value = parseInt(match[1], 10);
    const unit = match[2];
    const multipliers: Record<string, number> = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000,
    };

    return value * multipliers[unit];
  }
}
```

- [ ] Create LogoutUseCase — `src/modules/auth/application/use-cases/logout.use-case.ts`

```typescript
import { Inject, Injectable } from '@nestjs/common';
import {
  IRefreshTokenRepository,
  REFRESH_TOKEN_REPOSITORY,
} from '../../domain/refresh-token-repository.interface';

@Injectable()
export class LogoutUseCase {
  constructor(
    @Inject(REFRESH_TOKEN_REPOSITORY)
    private readonly refreshTokenRepository: IRefreshTokenRepository,
  ) {}

  async execute(userUid: string): Promise<void> {
    await this.refreshTokenRepository.revokeByUserUid(userUid);
  }
}
```

---

## 5. User Module Changes

- [ ] Add `findByUid` to IUserRepository — `src/modules/user/domain/user-repository.interface.ts`

```typescript
import { User } from './user.entity';

export const USER_REPOSITORY = Symbol('USER_REPOSITORY');

export interface IUserRepository {
  findByEmail(email: string): Promise<User | null>;
  findByUid(uid: string): Promise<User | null>;
  save(user: Partial<User>): Promise<User>;
}
```

- [ ] Implement `findByUid` in TypeOrmUserRepository — `src/modules/user/infrastructure/typeorm-user.repository.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../domain/user.entity';
import { IUserRepository } from '../domain/user-repository.interface';

@Injectable()
export class TypeOrmUserRepository implements IUserRepository {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email } });
  }

  async findByUid(uid: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { uid } });
  }

  async save(user: Partial<User>): Promise<User> {
    const newUser = this.userRepo.create(user);
    return this.userRepo.save(newUser);
  }
}
```

---

## 6. Infrastructure Layer (`src/modules/auth/infrastructure/`)

- [ ] Create TypeOrmRefreshTokenRepository — `src/modules/auth/infrastructure/typeorm-refresh-token.repository.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { LessThan, Repository } from 'typeorm';
import { RefreshToken } from '../domain/refresh-token.entity';
import { IRefreshTokenRepository } from '../domain/refresh-token-repository.interface';

@Injectable()
export class TypeOrmRefreshTokenRepository implements IRefreshTokenRepository {
  constructor(
    @InjectRepository(RefreshToken)
    private readonly repo: Repository<RefreshToken>,
  ) {}

  async save(token: Partial<RefreshToken>): Promise<RefreshToken> {
    const entity = this.repo.create(token);
    return this.repo.save(entity);
  }

  async findByTokenHash(tokenHash: string): Promise<RefreshToken | null> {
    return this.repo.findOne({
      where: { tokenHash },
      relations: ['user'],
    });
  }

  async revokeByUserUid(userUid: string): Promise<void> {
    await this.repo.update({ userUid, revoked: false }, { revoked: true });
  }

  async revokeByTokenHash(tokenHash: string): Promise<void> {
    await this.repo.update({ tokenHash }, { revoked: true });
  }

  async deleteExpired(): Promise<void> {
    await this.repo.delete({ expiresAt: LessThan(new Date()) });
  }
}
```

- [ ] Create JwtStrategy — `src/modules/auth/infrastructure/strategies/jwt.strategy.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../../application/interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
    });
  }

  validate(payload: JwtPayload) {
    return {
      uid: payload.sub,
      gid: payload.gid,
      email: payload.email,
    };
  }
}
```

- [ ] Create JwtAuthGuard — `src/modules/auth/infrastructure/guards/jwt-auth.guard.ts`

```typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
```

---

## 7. Presentation Layer (`src/modules/auth/presentation/`)

- [ ] Create AuthController — `src/modules/auth/presentation/auth.controller.ts`

```typescript
import {
  Body,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  UseGuards,
  Request,
} from '@nestjs/common';
import { LoginDto } from '../application/dto/login.dto';
import { RefreshTokenDto } from '../application/dto/refresh-token.dto';
import { AuthResponseDto } from '../application/dto/auth-response.dto';
import { LoginUseCase } from '../application/use-cases/login.use-case';
import { RefreshTokenUseCase } from '../application/use-cases/refresh-token.use-case';
import { LogoutUseCase } from '../application/use-cases/logout.use-case';
import { JwtAuthGuard } from '../infrastructure/guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly loginUseCase: LoginUseCase,
    private readonly refreshTokenUseCase: RefreshTokenUseCase,
    private readonly logoutUseCase: LogoutUseCase,
  ) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto): Promise<AuthResponseDto> {
    return this.loginUseCase.execute(dto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() dto: RefreshTokenDto): Promise<AuthResponseDto> {
    return this.refreshTokenUseCase.execute(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(JwtAuthGuard)
  async logout(@Request() req: { user: { uid: string } }): Promise<void> {
    await this.logoutUseCase.execute(req.user.uid);
  }
}
```

---

## 8. Module Wiring

- [ ] Create AuthModule — `src/modules/auth/auth.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from '../user/user.module';
import { RefreshToken } from './domain/refresh-token.entity';
import { REFRESH_TOKEN_REPOSITORY } from './domain/refresh-token-repository.interface';
import { TypeOrmRefreshTokenRepository } from './infrastructure/typeorm-refresh-token.repository';
import { JwtStrategy } from './infrastructure/strategies/jwt.strategy';
import { LoginUseCase } from './application/use-cases/login.use-case';
import { RefreshTokenUseCase } from './application/use-cases/refresh-token.use-case';
import { LogoutUseCase } from './application/use-cases/logout.use-case';
import { AuthController } from './presentation/auth.controller';

@Module({
  imports: [
    UserModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: config.get<string>('JWT_ACCESS_EXPIRATION', '15m'),
        },
      }),
    }),
    TypeOrmModule.forFeature([RefreshToken]),
  ],
  controllers: [AuthController],
  providers: [
    LoginUseCase,
    RefreshTokenUseCase,
    LogoutUseCase,
    JwtStrategy,
    {
      provide: REFRESH_TOKEN_REPOSITORY,
      useClass: TypeOrmRefreshTokenRepository,
    },
  ],
  exports: [JwtStrategy, JwtModule],
})
export class AuthModule {}
```

- [ ] Update AppModule — `src/app.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './modules/user/user.module';
import { AuthModule } from './modules/auth/auth.module';
import { HealthModule } from './modules/health/health.module';
import { User } from './modules/user/domain/user.entity';
import { RefreshToken } from './modules/auth/domain/refresh-token.entity';

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
        entities: [User, RefreshToken],
        synchronize: config.get<string>('NODE_ENV') !== 'production',
      }),
    }),
    UserModule,
    AuthModule,
    HealthModule,
  ],
})
export class AppModule {}
```

---

## 9. Testing

- [ ] Unit test: LoginUseCase — `src/modules/auth/application/use-cases/login.use-case.spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { LoginUseCase } from './login.use-case';
import { USER_REPOSITORY } from '../../../modules/user/domain/user-repository.interface';
import { REFRESH_TOKEN_REPOSITORY } from '../../domain/refresh-token-repository.interface';
import { InvalidCredentialsException } from '../../domain/exceptions/invalid-credentials.exception';

describe('LoginUseCase', () => {
  let useCase: LoginUseCase;
  const mockUserRepository = { findByEmail: jest.fn(), findByUid: jest.fn(), save: jest.fn() };
  const mockRefreshTokenRepository = {
    save: jest.fn(),
    findByTokenHash: jest.fn(),
    revokeByUserUid: jest.fn(),
    revokeByTokenHash: jest.fn(),
    deleteExpired: jest.fn(),
  };
  const mockJwtService = { sign: jest.fn() };
  const mockConfigService = { get: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LoginUseCase,
        { provide: USER_REPOSITORY, useValue: mockUserRepository },
        { provide: REFRESH_TOKEN_REPOSITORY, useValue: mockRefreshTokenRepository },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    useCase = module.get<LoginUseCase>(LoginUseCase);
    jest.clearAllMocks();
    mockConfigService.get.mockReturnValue('15m');
  });

  it('should return tokens on valid credentials', async () => {
    const hashedPassword = await bcrypt.hash('password123', 10);
    mockUserRepository.findByEmail.mockResolvedValue({
      uid: 'uid-1',
      gid: 'gid-1',
      email: 'test@example.com',
      password: hashedPassword,
    });
    mockJwtService.sign.mockReturnValue('access-token');
    mockRefreshTokenRepository.save.mockResolvedValue({});

    const result = await useCase.execute({
      email: 'test@example.com',
      password: 'password123',
    });

    expect(result.accessToken).toBe('access-token');
    expect(result.refreshToken).toBeDefined();
    expect(mockRefreshTokenRepository.save).toHaveBeenCalled();
  });

  it('should throw InvalidCredentialsException if user not found', async () => {
    mockUserRepository.findByEmail.mockResolvedValue(null);

    await expect(
      useCase.execute({ email: 'no@example.com', password: 'password123' }),
    ).rejects.toThrow(InvalidCredentialsException);
  });

  it('should throw InvalidCredentialsException if password is wrong', async () => {
    const hashedPassword = await bcrypt.hash('correctPassword', 10);
    mockUserRepository.findByEmail.mockResolvedValue({
      uid: 'uid-1',
      gid: 'gid-1',
      email: 'test@example.com',
      password: hashedPassword,
    });

    await expect(
      useCase.execute({ email: 'test@example.com', password: 'wrongPassword' }),
    ).rejects.toThrow(InvalidCredentialsException);
  });
});
```

- [ ] Unit test: RefreshTokenUseCase — `src/modules/auth/application/use-cases/refresh-token.use-case.spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RefreshTokenUseCase } from './refresh-token.use-case';
import { USER_REPOSITORY } from '../../../modules/user/domain/user-repository.interface';
import { REFRESH_TOKEN_REPOSITORY } from '../../domain/refresh-token-repository.interface';
import { InvalidRefreshTokenException } from '../../domain/exceptions/invalid-refresh-token.exception';

describe('RefreshTokenUseCase', () => {
  let useCase: RefreshTokenUseCase;
  const mockUserRepository = { findByEmail: jest.fn(), findByUid: jest.fn(), save: jest.fn() };
  const mockRefreshTokenRepository = {
    save: jest.fn(),
    findByTokenHash: jest.fn(),
    revokeByUserUid: jest.fn(),
    revokeByTokenHash: jest.fn(),
    deleteExpired: jest.fn(),
  };
  const mockJwtService = { sign: jest.fn() };
  const mockConfigService = { get: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RefreshTokenUseCase,
        { provide: USER_REPOSITORY, useValue: mockUserRepository },
        { provide: REFRESH_TOKEN_REPOSITORY, useValue: mockRefreshTokenRepository },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    useCase = module.get<RefreshTokenUseCase>(RefreshTokenUseCase);
    jest.clearAllMocks();
    mockConfigService.get.mockReturnValue('15m');
  });

  it('should issue new tokens on valid refresh token', async () => {
    const futureDate = new Date(Date.now() + 86400000);
    mockRefreshTokenRepository.findByTokenHash.mockResolvedValue({
      tokenHash: 'hash',
      userUid: 'uid-1',
      revoked: false,
      expiresAt: futureDate,
      user: { uid: 'uid-1', gid: 'gid-1', email: 'test@example.com' },
    });
    mockJwtService.sign.mockReturnValue('new-access-token');
    mockRefreshTokenRepository.revokeByTokenHash.mockResolvedValue(undefined);
    mockRefreshTokenRepository.save.mockResolvedValue({});

    const result = await useCase.execute({ refreshToken: 'valid-token' });

    expect(result.accessToken).toBe('new-access-token');
    expect(result.refreshToken).toBeDefined();
    expect(mockRefreshTokenRepository.revokeByTokenHash).toHaveBeenCalled();
    expect(mockRefreshTokenRepository.save).toHaveBeenCalled();
  });

  it('should throw if refresh token is revoked', async () => {
    mockRefreshTokenRepository.findByTokenHash.mockResolvedValue({
      tokenHash: 'hash',
      userUid: 'uid-1',
      revoked: true,
      expiresAt: new Date(Date.now() + 86400000),
      user: { uid: 'uid-1', gid: 'gid-1', email: 'test@example.com' },
    });

    await expect(
      useCase.execute({ refreshToken: 'revoked-token' }),
    ).rejects.toThrow(InvalidRefreshTokenException);
  });

  it('should throw if refresh token is expired', async () => {
    mockRefreshTokenRepository.findByTokenHash.mockResolvedValue({
      tokenHash: 'hash',
      userUid: 'uid-1',
      revoked: false,
      expiresAt: new Date(Date.now() - 1000),
      user: { uid: 'uid-1', gid: 'gid-1', email: 'test@example.com' },
    });

    await expect(
      useCase.execute({ refreshToken: 'expired-token' }),
    ).rejects.toThrow(InvalidRefreshTokenException);
  });

  it('should throw if refresh token not found', async () => {
    mockRefreshTokenRepository.findByTokenHash.mockResolvedValue(null);

    await expect(
      useCase.execute({ refreshToken: 'unknown-token' }),
    ).rejects.toThrow(InvalidRefreshTokenException);
  });
});
```

- [ ] Unit test: AuthController — `src/modules/auth/presentation/auth.controller.spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { LoginUseCase } from '../application/use-cases/login.use-case';
import { RefreshTokenUseCase } from '../application/use-cases/refresh-token.use-case';
import { LogoutUseCase } from '../application/use-cases/logout.use-case';

describe('AuthController', () => {
  let controller: AuthController;
  const mockLoginUseCase = { execute: jest.fn() };
  const mockRefreshTokenUseCase = { execute: jest.fn() };
  const mockLogoutUseCase = { execute: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        { provide: LoginUseCase, useValue: mockLoginUseCase },
        { provide: RefreshTokenUseCase, useValue: mockRefreshTokenUseCase },
        { provide: LogoutUseCase, useValue: mockLogoutUseCase },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    jest.clearAllMocks();
  });

  it('should call LoginUseCase on login', async () => {
    const dto = { email: 'test@example.com', password: 'password123' };
    const expected = {
      accessToken: 'token',
      refreshToken: 'refresh',
      expiresIn: '15m',
    };
    mockLoginUseCase.execute.mockResolvedValue(expected);

    const result = await controller.login(dto);
    expect(result).toEqual(expected);
    expect(mockLoginUseCase.execute).toHaveBeenCalledWith(dto);
  });

  it('should call RefreshTokenUseCase on refresh', async () => {
    const dto = { refreshToken: 'some-refresh-token' };
    const expected = {
      accessToken: 'new-token',
      refreshToken: 'new-refresh',
      expiresIn: '15m',
    };
    mockRefreshTokenUseCase.execute.mockResolvedValue(expected);

    const result = await controller.refresh(dto);
    expect(result).toEqual(expected);
  });

  it('should call LogoutUseCase on logout', async () => {
    mockLogoutUseCase.execute.mockResolvedValue(undefined);

    await controller.logout({ user: { uid: 'uid-1' } });
    expect(mockLogoutUseCase.execute).toHaveBeenCalledWith('uid-1');
  });
});
```

- [ ] E2E test: Auth endpoints — `test/auth.e2e-spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';

describe('Auth (e2e)', () => {
  let app: INestApplication;
  const testEmail = `auth-e2e-${Date.now()}@example.com`;
  const testPassword = 'securePass1';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();

    // Register a user first
    await request(app.getHttpServer())
      .post('/users/register')
      .send({
        serviceName: 'e2e-test',
        email: testEmail,
        password: testPassword,
      })
      .expect(201);
  });

  afterAll(async () => {
    await app.close();
  });

  it('POST /auth/login — valid credentials (200)', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: testEmail, password: testPassword })
      .expect(200);

    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
    expect(res.body.expiresIn).toBeDefined();
  });

  it('POST /auth/login — wrong password (401)', () => {
    return request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: testEmail, password: 'wrongPassword' })
      .expect(401);
  });

  it('POST /auth/login — non-existent user (401)', () => {
    return request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'noone@example.com', password: testPassword })
      .expect(401);
  });

  it('POST /auth/refresh — valid refresh token (200)', async () => {
    const loginRes = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: testEmail, password: testPassword })
      .expect(200);

    const res = await request(app.getHttpServer())
      .post('/auth/refresh')
      .send({ refreshToken: loginRes.body.refreshToken })
      .expect(200);

    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
  });

  it('POST /auth/refresh — reused token rejected (401)', async () => {
    const loginRes = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: testEmail, password: testPassword })
      .expect(200);

    // First refresh succeeds
    await request(app.getHttpServer())
      .post('/auth/refresh')
      .send({ refreshToken: loginRes.body.refreshToken })
      .expect(200);

    // Same token rejected (already revoked by rotation)
    await request(app.getHttpServer())
      .post('/auth/refresh')
      .send({ refreshToken: loginRes.body.refreshToken })
      .expect(401);
  });

  it('POST /auth/logout — authenticated user (204)', async () => {
    const loginRes = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: testEmail, password: testPassword })
      .expect(200);

    await request(app.getHttpServer())
      .post('/auth/logout')
      .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
      .expect(204);
  });

  it('POST /auth/logout — unauthenticated (401)', () => {
    return request(app.getHttpServer())
      .post('/auth/logout')
      .expect(401);
  });
});
```

---

## 10. Final File Structure

```
src/modules/auth/
  auth.module.ts
  application/
    dto/
      login.dto.ts
      auth-response.dto.ts
      refresh-token.dto.ts
    interfaces/
      jwt-payload.interface.ts
    use-cases/
      login.use-case.ts
      login.use-case.spec.ts
      refresh-token.use-case.ts
      refresh-token.use-case.spec.ts
      logout.use-case.ts
  domain/
    refresh-token.entity.ts
    refresh-token-repository.interface.ts
    exceptions/
      invalid-credentials.exception.ts
      invalid-refresh-token.exception.ts
  infrastructure/
    typeorm-refresh-token.repository.ts
    strategies/
      jwt.strategy.ts
    guards/
      jwt-auth.guard.ts
  presentation/
    auth.controller.ts
    auth.controller.spec.ts
```

---

## 11. API Summary

| Method | Endpoint         | Auth     | Body                               | Response            |
| ------ | ---------------- | -------- | ---------------------------------- | ------------------- |
| POST   | `/auth/login`    | None     | `{ email, password }`              | `200` — tokens      |
| POST   | `/auth/refresh`  | None     | `{ refreshToken }`                 | `200` — new tokens  |
| POST   | `/auth/logout`   | Bearer   | —                                  | `204` — no content  |

---

## 12. Final Review

- [ ] Verify `InvalidCredentialsException` uses same message for both "user not found" and "wrong password" (prevents email enumeration)
- [ ] Ensure refresh tokens are hashed before storage (never store plaintext)
- [ ] Confirm refresh token rotation (old token revoked on each refresh)
- [ ] Verify `JWT_SECRET` is not committed to source control
- [ ] Check that logout revokes all refresh tokens for the user
- [ ] Confirm `JwtAuthGuard` works on `POST /auth/logout`
