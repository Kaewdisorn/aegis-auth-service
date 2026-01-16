import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { ILogger } from '@application/ports/logger.interface';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT') || 3000;
  const logger = app.get(ILogger);

  await app.listen(port);
  logger.info(`Aegis Auth Service running on port ${port}`);
  logger.warn(`This is a warning message`);
  logger.error(`This is an error message`, `Error stack trace example`);
  logger.debug(`This is a debug message`);
}
bootstrap();
