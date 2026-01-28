import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { LoggerModule } from '@infrastructure/logging/logger.module';
import { AuthModule } from '@interfaces/http/auth.module';
import { AppConfigModule } from '@infrastructure/config/server-config.module';
import { CorrelationIdMiddleware } from '@infrastructure/middleware/correlation-id.middleware';
import { HttpLoggerMiddleware } from '@infrastructure/middleware/http-logger.middleware';


@Module({
  imports: [
    AppConfigModule,
    LoggerModule,
    AuthModule,
  ],
  controllers: [],
  providers: [],
})

export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(CorrelationIdMiddleware, HttpLoggerMiddleware)
      .forRoutes('*');
  }
}


