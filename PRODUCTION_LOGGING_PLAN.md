# Production-Grade Logging Implementation Plan
## Aegis Auth Service

**Date:** January 22, 2026  
**Last Updated:** January 27, 2026  
**Current Status:** Phase 1-3 Completed, Phase 4 Next  
**Goal:** Production-ready logging for a central authentication service

---

## Project Context

> From `.copilot-instructions.md`:
> - **Aegis Auth Service** is a reusable, production-grade authentication and identity service
> - Designed to be used by multiple backend services written in different languages
> - Follows **Clean Architecture**: domain → application → infrastructure → interfaces
> - **Avoid over-engineering** (no CQRS, no microservices, no unnecessary abstractions)
> - Code should reflect **real-world production standards** (Senior level 3-5 years)

---

## Architecture Alignment

### Logging Layer Placement (Clean Architecture)
```
┌─────────────────────────────────────────────────────────┐
│ interfaces/http     │ Controllers, Middleware           │
├─────────────────────────────────────────────────────────┤
│ application/ports   │ ILogger interface, LogMetadata    │
├─────────────────────────────────────────────────────────┤
│ infrastructure      │ WinstonLoggerService, Filters     │
└─────────────────────────────────────────────────────────┘
```

- **ILogger** defined in `application/ports` (abstraction)
- **WinstonLoggerService** in `infrastructure` (implementation)
- **Middleware & Filters** in `infrastructure` (framework concerns)
- **Domain layer** has NO logging dependencies

---

## Current State Assessment

### ✅ Completed
- ILogger interface abstraction in `application/ports`
- WinstonLoggerService with PII sanitization
- Exception filters (GlobalExceptionFilter, HttpExceptionFilter)
- Production file transports with daily rotation
- IAppConfig for centralized configuration
- Environment variables in `.env`

### 🔴 Remaining
- Request correlation/tracing
- HTTP request/response logging
- Auth event logging (security audit trail)

---

## ✅ Phase 1: Core Logger Interface & Service (COMPLETED)

**Files:**
- `src/application/ports/logger.interface.ts` - ILogger interface
- `src/infrastructure/logging/winston-logger.service.ts` - Implementation

**Completed:**
- ✅ Metadata support for structured logging
- ✅ Sensitive data sanitization (password, token, apiKey, etc.)
- ✅ Metadata enrichment (environment, serviceName, hostname, pid)
- ✅ Production JSON format / Development pretty format
- ✅ Unit tests updated for IAppConfig

---

## ✅ Phase 2: Exception Filters (COMPLETED)

**Files:**
- `src/infrastructure/filters/global-exception.filter.ts`
- `src/infrastructure/filters/http-exception.filter.ts`

**Completed:**
- ✅ Centralized error handling (aligns with project guidelines)
- ✅ Standardized error response format
- ✅ Correlation ID generation
- ✅ Log levels: 4xx → warn, 5xx → error
- ✅ Unit tests complete

---

## ✅ Phase 3: Production Configuration (COMPLETED)

**Files:**
- `src/application/ports/config.interface.ts` - IAppConfig
- `src/infrastructure/config/config.ts` - AppConfigService
- `.env` - Environment variables

**Completed:**
- ✅ IAppConfig interface with LoggerConfig
- ✅ Daily rotating file transports
- ✅ Environment-based configuration

---

## 🔴 Phase 4: HTTP Request Logging (NEXT)

> **Goal:** Trace every HTTP request through the system with correlation ID

### Step 4.1: Correlation ID Middleware
**File:** `src/infrastructure/middleware/correlation-id.middleware.ts`

```typescript
@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const correlationId = req.headers['x-correlation-id'] as string || uuidv4();
    req['correlationId'] = correlationId;
    res.setHeader('X-Correlation-ID', correlationId);
    next();
  }
}
```

**Why:** 
- Central auth service will be called by multiple backend services
- Correlation ID allows tracing requests across service boundaries
- Other services can pass `X-Correlation-ID` header to propagate trace

---

### Step 4.2: HTTP Logger Middleware
**File:** `src/infrastructure/middleware/http-logger.middleware.ts`

```typescript
@Injectable()
export class HttpLoggerMiddleware implements NestMiddleware {
  constructor(@Inject(ILogger) private readonly logger: ILogger) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    const { method, originalUrl, ip } = req;
    const correlationId = req['correlationId'];
    const userAgent = req.headers['user-agent'];

    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const { statusCode } = res;

      const metadata = {
        correlationId,
        method,
        path: originalUrl,
        statusCode,
        duration,
        ip,
        userAgent,
      };

      if (statusCode >= 500) {
        this.logger.error('HTTP Request', 'HttpLogger', undefined, metadata);
      } else if (statusCode >= 400) {
        this.logger.warn('HTTP Request', 'HttpLogger', metadata);
      } else {
        this.logger.info('HTTP Request', 'HttpLogger', metadata);
      }
    });

    next();
  }
}
```

---

### Step 4.3: Register Middleware
**File:** `src/app.module.ts`

```typescript
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(CorrelationIdMiddleware, HttpLoggerMiddleware)
      .forRoutes('*');
  }
}
```

---

### ❌ REMOVED: AsyncLocalStorage Service
> **Reason:** Over-engineering. Correlation ID stored in `req.correlationId` is sufficient.
> AsyncLocalStorage adds complexity without significant benefit for this service.

---

## 🔴 Phase 5: Auth Event Logging

> **Goal:** Security audit trail for authentication events (required for compliance)

### Step 5.1: Add Logging to Auth Use Cases
**Location:** `src/application/use-cases/` or `src/interfaces/http/controllers/`

**Events to log:**

| Event | Level | Metadata |
|-------|-------|----------|
| Login success | `info` | userId, username, ip, userAgent |
| Login failed | `warn` | username, reason, ip |
| Token issued | `debug` | userId, tokenType, expiresIn |
| Token refreshed | `debug` | userId |
| Logout | `info` | userId |
| Password changed | `info` | userId, changedBy |
| Account locked | `warn` | userId, reason, attempts |

**Example:**
```typescript
// In auth use case or controller
this.logger.info('User login successful', 'AuthService', {
  userId: user.id,
  username: user.username,
  action: 'LOGIN_SUCCESS',
  ip: request.ip,
  userAgent: request.headers['user-agent'],
});
```

---

### ❌ REMOVED: Separate Security Audit Logger Service
> **Reason:** Over-engineering. Use existing ILogger with proper metadata.
> The `action` field in metadata is sufficient to filter security events.

---

## ❌ Phase 6: REMOVED - Monitoring Integration

> **Reason:** Defer until production deployment.
> - Sentry integration - Add when deploying to production
> - Health checks - Not related to logging, separate concern
> - class-validator for config - Current config works fine

---

## 🟡 Phase 7: Testing & Documentation (PARTIAL)

### Completed Tests
- ✅ `winston-logger.service.spec.ts`
- ✅ `global-exception.filter.spec.ts`
- ✅ `http-exception.filter.spec.ts`

### TODO Tests
- `correlation-id.middleware.spec.ts`
- `http-logger.middleware.spec.ts`

---

## Implementation Progress

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Core Logger | ✅ COMPLETED |
| Phase 2 | Exception Filters | ✅ COMPLETED |
| Phase 3 | Production Config | ✅ COMPLETED |
| Phase 4 | HTTP Request Logging | 🔴 NEXT |
| Phase 5 | Auth Event Logging | 🔴 TODO |
| ~~Phase 6~~ | ~~Monitoring~~ | ❌ REMOVED |
| Phase 7 | Testing | 🟡 PARTIAL |

---

## Next Steps

1. **Phase 4.1:** Create `CorrelationIdMiddleware` (15 mins)
2. **Phase 4.2:** Create `HttpLoggerMiddleware` (30 mins)
3. **Phase 4.3:** Register middleware in AppModule (5 mins)
4. **Phase 4.4:** Add unit tests (30 mins)
5. **Phase 5:** Add auth event logging when auth features are implemented

---

## Files to Create/Modify

### New Files
- `src/infrastructure/middleware/correlation-id.middleware.ts`
- `src/infrastructure/middleware/http-logger.middleware.ts`
- `src/infrastructure/middleware/correlation-id.middleware.spec.ts`
- `src/infrastructure/middleware/http-logger.middleware.spec.ts`

### Modify
- `src/app.module.ts` - Register middleware

---

## Environment Variables (`.env`)

```bash
# Application
PORT=3000
HOST=localhost
NODE_ENV=development # {development, production}

# Logging
LOG_LEVEL=debug # {debug, info, warn, error}
LOG_DIR=./logs
ENABLE_FILE_LOGGING=false # Set to true in production
```

---

## Log Output Examples

### Development (Pretty)
```
2026-01-27 10:30:45.123 [info] [HttpLogger] HTTP Request
{
  "correlationId": "abc-123",
  "method": "POST",
  "path": "/auth/login",
  "statusCode": 200,
  "duration": 45
}
```

### Production (JSON)
```json
{"timestamp":"2026-01-27T10:30:45.123Z","level":"info","message":"HTTP Request","context":"HttpLogger","correlationId":"abc-123","method":"POST","path":"/auth/login","statusCode":200,"duration":45,"environment":"production","serviceName":"aegis-auth-service"}
```

---

**Plan Created:** January 22, 2026  
**Last Updated:** January 27, 2026  
**Status:** Phase 1-3 Completed ✅ | Phase 4 Next 🔴
