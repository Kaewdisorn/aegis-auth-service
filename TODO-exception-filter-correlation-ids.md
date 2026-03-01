# Global Exception Filter + Correlation IDs - Implementation Checklist

---

## 1. Install Dependencies

- [ ] Install `uuid` (already installed) — used for generating correlation IDs

```bash
# uuid is already in package.json — no install needed
```

---

## 2. Correlation ID Middleware (`src/shared/middleware/`)

- [ ] Create CorrelationIdMiddleware — `src/shared/middleware/correlation-id.middleware.ts`

```typescript
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

export const CORRELATION_ID_HEADER = 'x-request-id';

@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const correlationId =
      (req.headers[CORRELATION_ID_HEADER] as string) || uuidv4();

    req.headers[CORRELATION_ID_HEADER] = correlationId;
    res.setHeader(CORRELATION_ID_HEADER, correlationId);

    next();
  }
}
```

---

## 3. Error Response Interface (`src/shared/filters/`)

- [ ] Create error response type — `src/shared/filters/error-response.interface.ts`

```typescript
export interface ErrorResponse {
  statusCode: number;
  message: string | string[];
  error: string;
  correlationId: string;
  timestamp: string;
  path: string;
}
```

---

## 4. Global Exception Filter (`src/shared/filters/`)

- [ ] Create AllExceptionsFilter — `src/shared/filters/all-exceptions.filter.ts`

```typescript
import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { CORRELATION_ID_HEADER } from '../middleware/correlation-id.middleware';
import { ErrorResponse } from './error-response.interface';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    const correlationId =
      (request.headers[CORRELATION_ID_HEADER] as string) || 'unknown';

    const { statusCode, message, error } = this.extractInfo(exception);

    const errorResponse: ErrorResponse = {
      statusCode,
      message,
      error,
      correlationId,
      timestamp: new Date().toISOString(),
      path: request.url,
    };

    this.logException(exception, errorResponse);

    response.status(statusCode).json(errorResponse);
  }

  private extractInfo(exception: unknown): {
    statusCode: number;
    message: string | string[];
    error: string;
  } {
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
        const res = exceptionResponse as Record<string, unknown>;
        return {
          statusCode: status,
          message: (res.message as string | string[]) || exception.message,
          error: (res.error as string) || HttpStatus[status] || 'Error',
        };
      }

      return {
        statusCode: status,
        message: exception.message,
        error: HttpStatus[status] || 'Error',
      };
    }

    // Non-HTTP exceptions (unexpected errors)
    return {
      statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
      message: this.isProduction()
        ? 'An unexpected error occurred'
        : this.getExceptionMessage(exception),
      error: 'Internal Server Error',
    };
  }

  private logException(
    exception: unknown,
    errorResponse: ErrorResponse,
  ): void {
    const { statusCode, correlationId, path } = errorResponse;

    if (statusCode >= 500) {
      this.logger.error(
        `[${correlationId}] ${statusCode} ${path}`,
        exception instanceof Error ? exception.stack : String(exception),
      );
    } else {
      this.logger.warn(
        `[${correlationId}] ${statusCode} ${path} — ${JSON.stringify(errorResponse.message)}`,
      );
    }
  }

  private isProduction(): boolean {
    return process.env.NODE_ENV === 'production';
  }

  private getExceptionMessage(exception: unknown): string {
    if (exception instanceof Error) {
      return exception.message;
    }
    return String(exception);
  }
}
```

---

## 5. Register Middleware & Filter

- [ ] Register CorrelationIdMiddleware in AppModule — `src/app.module.ts`

```typescript
import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './modules/user/user.module';
import { HealthModule } from './modules/health/health.module';
import { User } from './modules/user/domain/user.entity';
import { CorrelationIdMiddleware } from './shared/middleware/correlation-id.middleware';

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
    HealthModule,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
  }
}
```

- [ ] Register AllExceptionsFilter globally in main.ts — `src/main.ts`

```typescript
import { NestFactory } from '@nestjs/core';
import { Logger, ValidationPipe } from '@nestjs/common';
import { WinstonModule } from 'nest-winston';
import { config } from 'dotenv';
import { AppModule } from './app.module';
import { createWinstonConfig } from './shared/logger/winston.config';
import { AllExceptionsFilter } from './shared/filters/all-exceptions.filter';

config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(createWinstonConfig(process.env.NODE_ENV)),
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.useGlobalFilters(new AllExceptionsFilter());

  app.enableShutdownHooks();

  const port = process.env.PORT ?? 3000;
  const host = process.env.HOST ?? 'localhost';
  await app.listen(port, host);

  const logger = new Logger('Bootstrap');
  logger.log(`Application is running on: http://${host}:${port}`);
  logger.log(`Environment: ${process.env.NODE_ENV ?? 'development'}`);
}
bootstrap();
```

---

## 6. Testing

- [ ] Unit test: AllExceptionsFilter — `src/shared/filters/all-exceptions.filter.spec.ts`

```typescript
import { ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { AllExceptionsFilter } from './all-exceptions.filter';

describe('AllExceptionsFilter', () => {
  let filter: AllExceptionsFilter;
  let mockResponse: { status: jest.Mock; json: jest.Mock };
  let mockRequest: { url: string; headers: Record<string, string> };
  let mockHost: ArgumentsHost;

  beforeEach(() => {
    filter = new AllExceptionsFilter();
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockRequest = {
      url: '/test',
      headers: { 'x-request-id': 'test-correlation-id' },
    };
    mockHost = {
      switchToHttp: () => ({
        getRequest: () => mockRequest,
        getResponse: () => mockResponse,
      }),
    } as unknown as ArgumentsHost;
  });

  it('should handle HttpException with correct status and shape', () => {
    const exception = new HttpException('Not Found', HttpStatus.NOT_FOUND);

    filter.catch(exception, mockHost);

    expect(mockResponse.status).toHaveBeenCalledWith(404);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 404,
        correlationId: 'test-correlation-id',
        path: '/test',
        timestamp: expect.any(String),
      }),
    );
  });

  it('should handle unknown exceptions as 500', () => {
    const exception = new Error('Something broke');

    filter.catch(exception, mockHost);

    expect(mockResponse.status).toHaveBeenCalledWith(500);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 500,
        error: 'Internal Server Error',
        correlationId: 'test-correlation-id',
      }),
    );
  });

  it('should include validation messages from class-validator', () => {
    const exception = new HttpException(
      {
        statusCode: 400,
        message: ['email must be an email', 'password is too short'],
        error: 'Bad Request',
      },
      HttpStatus.BAD_REQUEST,
    );

    filter.catch(exception, mockHost);

    expect(mockResponse.status).toHaveBeenCalledWith(400);
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        statusCode: 400,
        message: ['email must be an email', 'password is too short'],
        error: 'Bad Request',
      }),
    );
  });

  it('should use "unknown" when x-request-id header is missing', () => {
    mockRequest.headers = {};

    filter.catch(new Error('fail'), mockHost);

    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        correlationId: 'unknown',
      }),
    );
  });
});
```

- [ ] Unit test: CorrelationIdMiddleware — `src/shared/middleware/correlation-id.middleware.spec.ts`

```typescript
import { CorrelationIdMiddleware, CORRELATION_ID_HEADER } from './correlation-id.middleware';
import { Request, Response } from 'express';

describe('CorrelationIdMiddleware', () => {
  let middleware: CorrelationIdMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFn: jest.Mock;

  beforeEach(() => {
    middleware = new CorrelationIdMiddleware();
    mockRequest = { headers: {} };
    mockResponse = { setHeader: jest.fn() };
    nextFn = jest.fn();
  });

  it('should generate a new correlation ID when none is provided', () => {
    middleware.use(
      mockRequest as Request,
      mockResponse as Response,
      nextFn,
    );

    expect(mockRequest.headers![CORRELATION_ID_HEADER]).toBeDefined();
    expect(mockResponse.setHeader).toHaveBeenCalledWith(
      CORRELATION_ID_HEADER,
      expect.any(String),
    );
    expect(nextFn).toHaveBeenCalled();
  });

  it('should preserve an existing correlation ID from the request', () => {
    mockRequest.headers = { [CORRELATION_ID_HEADER]: 'existing-id' };

    middleware.use(
      mockRequest as Request,
      mockResponse as Response,
      nextFn,
    );

    expect(mockRequest.headers[CORRELATION_ID_HEADER]).toBe('existing-id');
    expect(mockResponse.setHeader).toHaveBeenCalledWith(
      CORRELATION_ID_HEADER,
      'existing-id',
    );
    expect(nextFn).toHaveBeenCalled();
  });
});
```

- [ ] E2E test: Error response shape — `test/error-responses.e2e-spec.ts`

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { AllExceptionsFilter } from '../src/shared/filters/all-exceptions.filter';

describe('Error Responses (e2e)', () => {
  let app: INestApplication;

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
    app.useGlobalFilters(new AllExceptionsFilter());
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('should return consistent error shape with correlationId on 400', async () => {
    const res = await request(app.getHttpServer())
      .post('/users/register')
      .send({ email: 'not-an-email', password: 'short' })
      .expect(400);

    expect(res.body).toEqual(
      expect.objectContaining({
        statusCode: 400,
        error: expect.any(String),
        message: expect.any(Array),
        correlationId: expect.any(String),
        timestamp: expect.any(String),
        path: '/users/register',
      }),
    );
  });

  it('should return x-request-id header in the response', async () => {
    const res = await request(app.getHttpServer())
      .post('/users/register')
      .send({ email: 'not-an-email', password: 'short' });

    expect(res.headers['x-request-id']).toBeDefined();
  });

  it('should propagate a provided x-request-id', async () => {
    const customId = 'my-custom-correlation-id';

    const res = await request(app.getHttpServer())
      .post('/users/register')
      .set('x-request-id', customId)
      .send({ email: 'not-an-email', password: 'short' })
      .expect(400);

    expect(res.headers['x-request-id']).toBe(customId);
    expect(res.body.correlationId).toBe(customId);
  });

  it('should return consistent error shape on 404', async () => {
    const res = await request(app.getHttpServer())
      .get('/nonexistent-route')
      .expect(404);

    expect(res.body).toEqual(
      expect.objectContaining({
        statusCode: 404,
        correlationId: expect.any(String),
        timestamp: expect.any(String),
        path: '/nonexistent-route',
      }),
    );
  });

  it('should return correlationId on 409 duplicate email', async () => {
    const email = `dup-err-${Date.now()}@example.com`;
    const dto = { serviceName: 'e2e-test', email, password: 'securePass1' };

    await request(app.getHttpServer())
      .post('/users/register')
      .send(dto)
      .expect(201);

    const res = await request(app.getHttpServer())
      .post('/users/register')
      .send(dto)
      .expect(409);

    expect(res.body.correlationId).toBeDefined();
    expect(res.body.statusCode).toBe(409);
  });
});
```

---

## 7. Final File Structure

```
src/shared/
  filters/
    all-exceptions.filter.ts
    all-exceptions.filter.spec.ts
    error-response.interface.ts
  middleware/
    correlation-id.middleware.ts
    correlation-id.middleware.spec.ts
  logger/
    winston.config.ts
```

---

## 8. Response Shape — Before vs After

**Before** (inconsistent, NestJS defaults):

```json
{
  "statusCode": 400,
  "message": ["email must be an email"],
  "error": "Bad Request"
}
```

**After** (consistent, with correlation ID):

```json
{
  "statusCode": 400,
  "message": ["email must be an email"],
  "error": "Bad Request",
  "correlationId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "timestamp": "2026-03-01T12:00:00.000Z",
  "path": "/users/register"
}
```

---

## 9. Final Review

- [ ] Verify all error responses include `correlationId`, `timestamp`, and `path`
- [ ] Confirm stack traces are stripped in production (`NODE_ENV=production`)
- [ ] Verify `x-request-id` header is propagated when provided by caller
- [ ] Verify `x-request-id` header is generated when not provided
- [ ] Check that `ValidationPipe` errors go through the filter and keep array messages
- [ ] Confirm 500 errors log full stack traces server-side
