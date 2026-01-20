import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { LoggerModule } from '@infrastructure/logging/logger.module';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from '@interfaces/http/auth.module';
import { HttpLoggerMiddleware } from '@infrastructure/middleware/http-logger.middleware';


@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    LoggerModule,
    AuthModule
  ],
  controllers: [],
  providers: [],
})

export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(HttpLoggerMiddleware)
      .forRoutes('*');
  }
}
