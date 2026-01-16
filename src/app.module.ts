import { Module } from '@nestjs/common';
import { LoggerModule } from '@infrastructure/logging/logger.module';


@Module({
  imports: [LoggerModule],
  controllers: [],
  providers: [],
})
export class AppModule { }
