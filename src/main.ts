import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { ILogger } from '@application/ports/logger.interface';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const logger = app.get(ILogger);

  const configService = app.get(ConfigService);
  const host = configService.get<string>('HOST') || 'localhost';
  const port = configService.get<number>('PORT') || 3000;

  await app.listen(port);
  logger.info('Aegis Auth Service running on ' + `http://${host}:${port}`);
}
bootstrap();
