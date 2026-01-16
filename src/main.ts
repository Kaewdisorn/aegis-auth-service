import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ILogger } from '@application/ports/logger.interface';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const logger = app.get(ILogger);
  const port = process.env.PORT || 3000;

  await app.listen(port);
  logger.info(`Aegis Auth Service running on port ${port}`);
}
bootstrap();
