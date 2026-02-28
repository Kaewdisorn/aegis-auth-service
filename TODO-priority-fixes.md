# Priority Order for Fixes

## Completed

- [x] **1. Add `@Injectable()` to `TypeOrmUserRepository`**
- [x] **2. Fix e2e tests — add `serviceName` to all test payloads**
- [x] **3. Enable `strict: true` in tsconfig**
- [x] **4. Add health check + graceful shutdown**

## Remaining

- [ ] **5. Add rate limiting, Helmet, CORS** _(Small)_
  - Add `@nestjs/throttler` to prevent brute-force registration
  - Add `helmet` middleware for security headers
  - Configure `app.enableCors()` with explicit origin whitelist

- [ ] **6. Strengthen password validation + email normalization** _(Small)_
  - Add `@Matches()` requiring uppercase, lowercase, digit, special character
  - Normalize email (trim + lowercase) before lookup and save
  - Prevents weak passwords and duplicate accounts via case variation

- [ ] **7. Add global exception filter + correlation IDs** _(Medium)_
  - Create a catch-all exception filter to normalize error responses
  - Strip stack traces in production
  - Add middleware to generate/propagate `X-Request-Id` for distributed tracing

- [ ] **8. Add Swagger/OpenAPI docs** _(Medium)_
  - Install `@nestjs/swagger`
  - Add decorators to DTOs and controllers
  - Enables API documentation and contract testing

- [ ] **9. Add Dockerfile + `.env.example`** _(Small)_
  - Multi-stage Dockerfile for the application
  - `.env.example` documenting all required environment variables
  - Improves deployability and developer onboarding

- [ ] **10. Decouple domain entity from TypeORM** _(Large)_
  - Separate plain domain class from TypeORM schema/entity
  - Map between domain and persistence models in the repository layer
  - Achieves clean architecture — domain layer free of infrastructure concerns
