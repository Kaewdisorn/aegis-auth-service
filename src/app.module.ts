import { Module } from '@nestjs/common';
import { LoggerModule } from '@infrastructure/logging/logger.module';
import { ConfigModule } from '@nestjs/config';


@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    LoggerModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule { }
