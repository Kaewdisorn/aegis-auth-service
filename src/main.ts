import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { ILogger } from '@application/ports/logger.interface';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const logger = app.get<ILogger>(ILogger);
  const configService = app.get(ConfigService);
  const host = configService.get<string>('HOST') || 'localhost';
  const port = configService.get<number>('PORT') || 3000;
  const nodeEnv = configService.get<string>('NODE_ENV') || 'development';

  logger.info('Starting Aegis Auth Service...', 'Bootstrap', {
    environment: nodeEnv,
    nodeVersion: process.version,
    pid: process.pid,
  });

  try {
    await app.listen(port);

    // logger.info(`Aegis Auth Service started successfully`, 'Bootstrap', {
    //   url: `http://${host}:${port}`,
    //   environment: nodeEnv,
    //   port,
    //   host,
    // });

    // logger.info('Service health check passed', 'Bootstrap', {
    //   status: 'healthy',
    //   uptime: process.uptime(),
    // });
  } catch (error) {
    // logger.error(
    //   'Failed to start Aegis Auth Service',
    //   error.stack,
    //   'Bootstrap',
    //   {
    //     error: error.message,
    //     port,
    //     host,
    //   }
    // );
    process.exit(1);
  }



}
bootstrap();
