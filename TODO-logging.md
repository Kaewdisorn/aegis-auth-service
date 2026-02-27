# Logging System (Winston) - Implementation Checklist

---

## 1. Install Dependencies

- [x] Install Winston & NestJS integration

```bash
npm install nest-winston winston
```

---

## 2. Logger Configuration (`src/shared/logger/`)

- [x] Create Winston config — `src/shared/logger/winston.config.ts`

```typescript
import { utilities } from 'nest-winston';
import * as winston from 'winston';

const isProduction = process.env.NODE_ENV === 'production';

export const winstonConfig = {
  transports: [
    // Development: pretty-printed console output
    ...(!isProduction
      ? [
          new winston.transports.Console({
            format: winston.format.combine(
              winston.format.timestamp(),
              utilities.format.nestLike('AegisAuth', {
                prettyPrint: true,
                colors: true,
              }),
            ),
          }),
        ]
      : []),

    // Production: structured JSON for log aggregators
    ...(isProduction
      ? [
          new winston.transports.Console({
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json(),
            ),
          }),
        ]
      : []),
  ],
};
```

---

## 3. Bootstrap Integration

- [x] Replace default logger in `src/main.ts`

```typescript
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';
import { AppModule } from './app.module';
import { winstonConfig } from './shared/logger/winston.config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
  });

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

## 4. Usage in Services

- [ ] Add logging to `RegisterUserUseCase` — `src/modules/user/application/use-cases/register-user.use-case.ts`

```typescript
import { Inject, Injectable, Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {
  IUserRepository,
  USER_REPOSITORY,
} from '../../domain/user-repository.interface';
import { UserAlreadyExistsException } from '../../domain/exceptions/user-already-exists.exception';
import { RegisterUserDto } from '../dto/register-user.dto';
import { UserResponseDto } from '../dto/user-response.dto';

@Injectable()
export class RegisterUserUseCase {
  private readonly logger = new Logger(RegisterUserUseCase.name);

  constructor(
    @Inject(USER_REPOSITORY)
    private readonly userRepository: IUserRepository,
  ) {}

  async execute(dto: RegisterUserDto): Promise<UserResponseDto> {
    this.logger.log(`Attempting registration for: ${dto.email}`);

    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      this.logger.warn(`Duplicate registration attempt: ${dto.email}`);
      throw new UserAlreadyExistsException(dto.email);
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.userRepository.save({
      email: dto.email,
      password: hashedPassword,
    });

    this.logger.log(`User registered successfully: ${user.id}`);
    return UserResponseDto.fromEntity(user);
  }
}
```

---

## 5. Verification

- [ ] Dev mode: confirm pretty-printed colored logs in console
- [ ] Production mode: set `NODE_ENV=production` and verify JSON output
- [ ] Ensure no sensitive data (passwords) appears in logs
- [ ] Confirm log levels are correct (`log` for success, `warn` for conflicts, `error` for failures)
