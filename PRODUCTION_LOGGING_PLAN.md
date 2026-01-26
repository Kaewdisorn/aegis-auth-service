# Production-Grade Logging Implementation Plan
## Aegis Auth Service

**Date:** January 22, 2026  
**Current Status:** Development-grade logging with Winston  
**Goal:** Transform to enterprise-ready production logging

---

## Current State Assessment

### ✅ Strengths
- Clean architecture with ILogger interface abstraction
- Dependency injection properly implemented
- Global module for easy access
- Good test coverage for existing implementation
- Winston is a solid logging library choice

### ❌ Critical Gaps
- No production logging enabled (file transports commented out)
- Zero error handling/exception filters
- No structured logging capabilities (no metadata support)
- Minimal logging in application logic
- No request correlation/tracing
- Console.log still present in middleware
- No PII/sensitive data sanitization
- No external monitoring integrations
- No security audit logging

---

## ✅ Phase 1: Enhance Core Logger Interface & Service (COMPLETED)

### ✅ Step 1.1: Extend ILogger Interface
**File:** `src/application/ports/logger.interface.ts`

**✅ Completed Changes:**
- ✅ Added method overloads to support optional metadata parameter
- ✅ Maintained backward compatibility with existing signatures
- ✅ Defined TypeScript types:
  - `LogMetadata` - General metadata object
  - `SecurityContext` - User/auth context
  - `PerformanceMetrics` - Timing/performance data
  - `RequestContext` - HTTP request details
  - `ExtendedLogMetadata` - Combined metadata type

**Impact:** Enables structured logging throughout application

---

### ✅ Step 1.2: Update WinstonLoggerService
**File:** `src/infrastructure/logging/winston-logger.service.ts`

**✅ Completed Changes:**
1. ✅ Modified all methods (info, error, warn, debug) to accept metadata parameter
2. ✅ Added `sanitizeMetadata()` method to redact sensitive fields:
   - password, token, accessToken, refreshToken
   - authorization, cookie, secret, apiKey
   - creditCard, ssn, etc.
3. ✅ Added `enrichMetadata()` method to auto-add:
   - environment (NODE_ENV)
   - serviceName
   - hostname
   - pid (process ID)
4. ✅ Updated console format to display metadata in pretty JSON
5. ✅ Implemented deep sanitization (nested objects and arrays)
6. ✅ Added production-ready file transports with daily rotation

**Impact:** Safe structured logging with automatic PII protection

---

### ✅ Step 1.3: Update Tests
**File:** `src/infrastructure/logging/winston-logger.service.spec.ts`

**✅ Completed Test Suites:**
1. ✅ **Metadata support** - Test all log levels accept and pass metadata
2. ✅ **Sensitive data sanitization** - Verify password, token, etc. are redacted
3. ✅ **Nested sanitization** - Test deep object and array sanitization
4. ✅ **Metadata enrichment** - Verify auto-added fields (environment, serviceName, etc.)

**Coverage:** 88.88% statement coverage, 27 tests passing

---

## ✅ Phase 2: Implement Exception Filters (COMPLETED)

### ✅ Step 2.1: Create Global Exception Filter
**File:** `src/infrastructure/filters/global-exception.filter.ts`

**✅ Completed:**
- ✅ Implements `ExceptionFilter` with `@Catch()` decorator (catches all exceptions)
- ✅ Injects `ILogger` for error logging
- ✅ Logs exceptions with full context:
  - ✅ Stack trace (via metadata)
  - ✅ Request URL, method, headers
  - ✅ User context (if available)
  - ✅ Correlation ID (generated via uuid)
  - ✅ Timestamp
- ✅ Returns standardized error response with: statusCode, message, error, correlationId, timestamp, path
- ✅ `sanitizeMessage()` - Hides sensitive error details in production (5xx → "Internal server error")
- ✅ `sanitizeHeaders()` - Redacts authorization, cookie, x-api-key, x-auth-token

**Impact:** All unhandled exceptions are logged and handled gracefully

---

### ✅ Step 2.2: Create HTTP Exception Filter
**File:** `src/infrastructure/filters/http-exception.filter.ts`

**✅ Completed:**
- ✅ Implements `ExceptionFilter` with `@Catch(HttpException)` decorator
- ✅ Handles NestJS HTTP exceptions specifically (400, 401, 403, 404, etc.)
- ✅ Logs with appropriate level:
  - 4xx status codes → warn level
  - 5xx status codes → error level (with stack trace)
- ✅ Parses validation errors (string or object with message array)
- ✅ Includes request context in logs (method, path, ip, userAgent, correlationId)
- ✅ Returns standardized error response with: statusCode, message, error, correlationId, timestamp, path

**Impact:** Proper handling and logging of HTTP errors with appropriate log levels

---

### ✅ Step 2.3: Register Filters in Main
**File:** `src/main.ts`

**✅ Completed:**
- ✅ GlobalExceptionFilter registered via `app.useGlobalFilters()`
- ✅ HttpExceptionFilter registered LAST (higher priority in NestJS filter chain)
- ✅ Correct order: GlobalExceptionFilter first, HttpExceptionFilter last

```typescript
app.useGlobalFilters(
  new GlobalExceptionFilter(logger),  // Lower priority - catches non-HTTP exceptions
  new HttpExceptionFilter(logger),    // Higher priority - catches HttpException first
);
```

---

### ✅ Step 2.4: Add Unit Tests
**File:** `src/infrastructure/filters/global-exception.filter.spec.ts`

**✅ Completed Test Suites:**
- ✅ Generic Error handling (returns 500)
- ✅ HttpException handling (preserves status code)
- ✅ Header sanitization (authorization, cookie, x-api-key, x-auth-token)
- ✅ User context inclusion
- ✅ Correlation ID generation/propagation
- ✅ Production vs development response format

**File:** `src/infrastructure/filters/http-exception.filter.spec.ts`

**✅ Completed Test Suites:**
- ✅ 4xx Client Errors - logs at warn level (400, 401, 403, 404, 422, 429)
- ✅ 5xx Server Errors - logs at error level with stack trace (500, 502, 503, 504)
- ✅ Message parsing (string, object, validation arrays)
- ✅ Response format (statusCode, message, error, correlationId, timestamp, path)
- ✅ Log metadata (request context, correlationId)
- ✅ Different HTTP methods (GET, POST, PUT, DELETE)

---

## Phase 3: Production Log Transports & Configuration

### Step 3.1: Create Environment Configuration
**New file:** `src/infrastructure/config/logger.config.ts`

**Define Configuration Interface:**
```typescript
interface LoggerConfig {
  logLevel: string;           // debug, info, warn, error
  enableFileLogging: boolean; // Enable file transports
  logDir: string;            // Directory for log files
  maxFiles: number;          // Rotation retention
  maxSize: string;           // File size before rotation
  enableJsonFormat: boolean;  // JSON vs pretty print
  enableConsole: boolean;     // Console output
  enableDailyRotate: boolean; // Date-based rotation
}
```

**Validation:**
- Use class-validator for environment variable validation
- Provide sensible defaults
- Fail fast on invalid configuration

**Impact:** Type-safe, validated logging configuration

---

### Step 3.2: Update Winston Transports
**File:** `src/infrastructure/logging/winston-logger.service.ts`

**Changes:**
1. **Uncomment file transports** (lines 33-51)
2. **Environment-based configuration:**
   - **Development:** Colorized console + pretty format, no files
   - **Production:** JSON console + file rotation
3. **File transport setup:**
   - Error log: `logs/error.log` (error level only)
   - Combined log: `logs/combined.log` (all levels)
   - Daily rotation with date pattern: `logs/app-%DATE%.log`
   - Max file size: 20MB
   - Retention: 14 days
   - Compression: gzip old logs
4. **JSON format for production:**
   ```json
   {
     "timestamp": "2026-01-22T10:30:45.123Z",
     "level": "info",
     "message": "User logged in",
     "context": "AuthController",
     "correlationId": "uuid",
     "userId": "123",
     "environment": "production",
     "serviceName": "aegis-auth-service"
   }
   ```
5. **Install winston-daily-rotate-file:**
   ```bash
   npm install winston-daily-rotate-file
   ```

**Impact:** Production-ready log persistence and rotation

---

### Step 3.3: Create .env.example
**New file:** `.env.example`

**Document all environment variables:**
```bash
# Application
NODE_ENV=development
HOST=localhost
PORT=3000

# Logging
LOG_LEVEL=info
LOG_DIR=./logs
ENABLE_FILE_LOGGING=false
ENABLE_JSON_LOGS=false
LOG_MAX_FILES=14
LOG_MAX_SIZE=20m

# Database (future)
# DB_HOST=localhost
# DB_PORT=5432

# Security (future)
# JWT_SECRET=your-secret-key
```

**Impact:** Clear documentation for deployment

---

## Phase 4: Correlation ID & Request Context

### Step 4.1: Create Correlation ID Middleware
**New file:** `src/infrastructure/middleware/correlation-id.middleware.ts`

**Implementation:**
- Generate UUID v4 for each request
- Check for existing `X-Correlation-ID` header (propagate from upstream)
- Store correlation ID in request object: `req.correlationId`
- Set response header: `X-Correlation-ID`
- Must execute BEFORE HttpLoggerMiddleware

**Impact:** Request tracing across entire application

---

### Step 4.2: Create Async Context Service
**New file:** `src/infrastructure/context/async-context.service.ts`
**New file:** `src/infrastructure/context/async-context.module.ts`

**Implementation:**
- Use Node.js `AsyncLocalStorage` for request context
- Store per-request data:
  - correlationId
  - requestId
  - userId (after authentication)
  - tenantId (for multi-tenant)
  - startTime (for duration calculation)
- Provide methods:
  - `setContext(key, value)`
  - `getContext(key)`
  - `getCorrelationId()`
  - `getUserContext()`
  - `clear()`
- Global module for injection anywhere

**Impact:** Automatic context propagation without manual passing

---

### Step 4.3: Update HttpLoggerMiddleware
**File:** `src/infrastructure/middleware/http-logger.middleware.ts`

**Changes:**
1. **Remove** `console.log` statement (line 10)
2. Inject `AsyncContextService`
3. Get correlation ID from context
4. **Log request** with metadata:
   - method, path, correlationId
   - userAgent, ip
   - headers (sanitized)
   - query params
5. **Log response** using `res.on('finish')`:
   - statusCode
   - duration (ms)
   - contentLength
6. **Optional:** Log request/response body (sanitized, configurable)
7. Use different log levels:
   - 2xx → info
   - 4xx → warn
   - 5xx → error

**Impact:** Comprehensive HTTP request/response logging

---

### Step 4.4: Update WinstonLoggerService
**File:** `src/infrastructure/logging/winston-logger.service.ts`

**Changes:**
- Inject `AsyncContextService` (optional dependency)
- In `enrichMetadata()`: Auto-include correlationId from context
- All logs automatically include correlation ID

**Impact:** Every log entry traceable to originating request

---

### Step 4.5: Register Middleware in AppModule
**File:** `src/app.module.ts`

**Changes:**
- Import both middleware classes
- Configure in correct order:
  1. `CorrelationIdMiddleware` (first)
  2. `HttpLoggerMiddleware` (second)
- Apply to all routes with `consumer.apply().forRoutes('*')`

**Impact:** Request tracing active for all endpoints

---

## Phase 5: Business Logic & Security Logging

### Step 5.1: Enhance Auth Controller
**File:** `src/interfaces/http/controllers/auth.controller.ts`

**Add logging for:**
- **Successful login:**
  ```typescript
  this.logger.info('User login successful', 'AuthController', {
    userId: user.id,
    username: user.username,
    action: 'login',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
  });
  ```
- **Failed login attempt:**
  ```typescript
  this.logger.warn('Login attempt failed', 'AuthController', {
    username: dto.username,
    reason: 'invalid_credentials',
    ipAddress: req.ip,
  });
  ```
- **Token generation:**
  ```typescript
  this.logger.debug('JWT token generated', 'AuthController', {
    userId: user.id,
    expiresIn: '1h',
  });
  ```
- **Token validation:**
  ```typescript
  this.logger.debug('Token validated', 'AuthController', {
    userId: payload.sub,
  });
  ```
- **Logout:**
  ```typescript
  this.logger.info('User logged out', 'AuthController', {
    userId: user.id,
  });
  ```

**Impact:** Full audit trail of authentication events

---

### Step 5.2: Create Security Audit Logger
**New file:** `src/infrastructure/logging/security-audit.logger.ts`
**New file:** `src/infrastructure/logging/security-audit.module.ts`

**Implementation:**
- Specialized service extending WinstonLoggerService
- Separate file transport: `logs/security-audit.log`
- Structured methods:
  - `logAuthenticationAttempt(success, userId, username, ip, userAgent)`
  - `logAuthorizationFailure(userId, resource, action, reason)`
  - `logTokenGeneration(userId, tokenType, expiresIn)`
  - `logTokenValidation(success, userId, reason)`
  - `logPasswordChange(userId, changedBy)`
  - `logSuspiciousActivity(userId, activityType, details)`
- Always include: timestamp, correlationId, userId, action, result, ipAddress
- Never log sensitive data (passwords, tokens)
- Retention: 90 days (compliance requirement)

**Impact:** Security audit trail for compliance (SOC 2, GDPR, etc.)

---

## Phase 6: Configuration & Monitoring Integration

### Step 6.1: Create Configuration Module
**New file:** `src/infrastructure/config/config.module.ts`
**New files:** Typed config services for each domain

**Implementation:**
- Use `@nestjs/config` with validation
- Separate config classes:
  - `LoggerConfig`
  - `DatabaseConfig`
  - `AuthConfig`
  - `AppConfig`
- Load environment-specific files:
  - `.env.development`
  - `.env.staging`
  - `.env.production`
- Validate with `class-validator`:
  ```typescript
  @IsEnum(['development', 'staging', 'production'])
  NODE_ENV: string;
  
  @IsIn(['debug', 'info', 'warn', 'error'])
  LOG_LEVEL: string;
  ```
- Fail fast on validation errors
- Export typed providers for DI

**Impact:** Type-safe, validated configuration management

---

### Step 6.2: Add Error Tracking Integration (Optional)
**New file:** `src/infrastructure/monitoring/sentry.module.ts`

**If using Sentry:**
1. Install dependencies:
   ```bash
   npm install @sentry/node @sentry/tracing
   ```
2. Initialize Sentry in `main.ts`:
   ```typescript
   Sentry.init({
     dsn: configService.get('SENTRY_DSN'),
     environment: configService.get('NODE_ENV'),
     tracesSampleRate: 1.0,
   });
   ```
3. Create custom Winston transport for Sentry:
   - Send error level logs to Sentry
   - Include breadcrumbs
   - Add user context
   - Add tags (environment, version, correlationId)
4. Add Sentry error interceptor

**Impact:** Real-time error tracking and alerting

---

### Step 6.3: Add Health Check Logging
**Files:** Health check endpoint (if missing, create it)

**Implementation:**
- Create health check module with `@nestjs/terminus`
- Log health check calls at debug level
- Log service degradation at warn level
- Log failures at error level
- Include in logs:
  - Check type (database, memory, disk)
  - Status (healthy, degraded, unhealthy)
  - Response time
  - Details of failed checks

**Impact:** Operational visibility into service health

---

## Phase 7: Testing & Documentation

### Step 7.1: Update All Tests

**New test files:**
- `global-exception.filter.spec.ts`
- `http-exception.filter.spec.ts`
- `correlation-id.middleware.spec.ts`
- `async-context.service.spec.ts`
- `security-audit.logger.spec.ts`

**Update existing:**
- `winston-logger.service.spec.ts` (new metadata tests)
- `http-logger.middleware.spec.ts` (correlation ID, duration)

**E2E tests:**
- Test exception filters with actual HTTP requests
- Test correlation ID propagation
- Test log output format

**Target:** 90%+ code coverage

---

### Step 7.2: Update README
**File:** `README.md`

**Add sections:**
1. **Logging Configuration**
   - Environment variables
   - Log levels
   - File locations
2. **Log Formats**
   - Development vs Production
   - Example log entries
   - JSON structure
3. **Correlation IDs**
   - How to propagate
   - How to search logs
4. **Security Logging**
   - What events are logged
   - Retention policy
   - Compliance notes
5. **Troubleshooting**
   - How to enable debug logging
   - How to tail logs
   - How to search logs

**Impact:** Developer onboarding and operational runbooks

---

## Implementation Order

### **Start Here (High Priority)**
1. ✅ **Phase 1** - Core logging enhancement (COMPLETED ✅)
2. ✅ **Phase 2** - Exception filters (COMPLETED ✅)
   - ✅ GlobalExceptionFilter implemented
   - ✅ HttpExceptionFilter implemented
   - ✅ Unit tests complete for both filters
3. 🔴 **Phase 3** - Production transports (1-2 hours) → Partially done in Phase 1

### **Then Continue (Medium Priority)**
4. 🟡 **Phase 4** - Correlation IDs (3-4 hours) → Observability
5. 🟡 **Phase 5** - Security logging (2-3 hours) → Auth service requirement

### **Finally (Nice-to-Have)**
6. 🟢 **Phase 6** - Advanced config & monitoring (4-6 hours)
7. 🟢 **Phase 7** - Testing & docs (3-4 hours)

**Total Estimated Time:** 17-24 hours of development

### **Phase 2 Completed! ✅**
- ✅ `src/infrastructure/filters/global-exception.filter.ts`
- ✅ `src/infrastructure/filters/http-exception.filter.ts`
- ✅ `src/infrastructure/filters/global-exception.filter.spec.ts`
- ✅ `src/infrastructure/filters/http-exception.filter.spec.ts`
- ✅ `src/main.ts` - Filters registered in correct order

---

## Dependencies to Install

```bash
# Required
npm install winston-daily-rotate-file

# Optional (monitoring)
npm install @sentry/node @sentry/tracing

# Optional (health checks)
npm install @nestjs/terminus

# Dev dependencies (if missing)
npm install -D @types/express
```

---

## Configuration Checklist

### Development Environment
- [ ] LOG_LEVEL=debug
- [ ] ENABLE_FILE_LOGGING=false
- [ ] ENABLE_JSON_LOGS=false
- [ ] Console output with colors

### Staging Environment
- [ ] LOG_LEVEL=info
- [ ] ENABLE_FILE_LOGGING=true
- [ ] ENABLE_JSON_LOGS=true
- [ ] File rotation enabled

### Production Environment
- [ ] LOG_LEVEL=info (or warn)
- [ ] ENABLE_FILE_LOGGING=true
- [ ] ENABLE_JSON_LOGS=true
- [ ] External log aggregation configured
- [ ] Error tracking enabled (Sentry)
- [ ] Alerts configured
- [ ] Log retention policy enforced

---

## Success Metrics

### Technical Metrics
- ✅ 100% of unhandled exceptions logged
- ✅ 100% of HTTP requests logged with correlation ID
- ✅ 100% of auth events logged to security audit log
- ✅ 0 sensitive data leaks in logs
- ✅ 90%+ test coverage
- ✅ Log files rotate automatically
- ✅ Logs searchable by correlation ID

### Operational Metrics
- ✅ Mean time to detect (MTTD) issues < 5 minutes
- ✅ Mean time to resolve (MTTR) reduced by 50%
- ✅ Zero incidents of PII exposure in logs
- ✅ Compliance audit ready

---

## Future Enhancements

1. **Distributed Tracing**
   - OpenTelemetry integration
   - Jaeger or Zipkin
   - Trace ID propagation

2. **Log Aggregation**
   - Elasticsearch + Kibana (ELK stack)
   - CloudWatch Logs (AWS)
   - Datadog or New Relic

3. **Metrics & APM**
   - Prometheus metrics
   - Grafana dashboards
   - Application Performance Monitoring

4. **Advanced Features**
   - Dynamic log level adjustment (without restart)
   - Log sampling for high-volume endpoints
   - Structured logging for database queries
   - Business metrics logging

---

## Resources & References

- [Winston Documentation](https://github.com/winstonjs/winston)
- [NestJS Logging](https://docs.nestjs.com/techniques/logger)
- [NestJS Exception Filters](https://docs.nestjs.com/exception-filters)
- [AsyncLocalStorage](https://nodejs.org/api/async_context.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

**Plan Created:** January 22, 2026  
**Last Updated:** January 24, 2026  
**Status:** Phase 1 Completed ✅ | Phase 2 Completed ✅ | Phase 3 Next 🔴
