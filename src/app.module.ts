import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { LoggerModule } from '@infrastructure/logging/logger.module';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from '@interfaces/http/auth.module';
import { ServerConfigModule } from '@infrastructure/config/server-config.module';


@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    ServerConfigModule,
    LoggerModule,
    AuthModule
  ],
  controllers: [],
  providers: [],
})

export class AppModule { }


