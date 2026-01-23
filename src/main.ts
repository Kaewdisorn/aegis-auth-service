import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { ILogger } from '@application/ports/logger.interface';
import { GlobalExceptionFilter } from '@infrastructure/filters/global-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: false,
  });
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

  app.useGlobalFilters(new GlobalExceptionFilter(logger));

  try {
    await app.listen(port);

    logger.info(`Aegis Auth Service started successfully`, 'Bootstrap', {
      url: `http://${host}:${port}`,
      environment: nodeEnv,
      port,
      host,
    });

    logger.info('Service health check passed', 'Bootstrap', {
      status: 'healthy',
      uptime: process.uptime(),
    });
  } catch (error) {
    logger.error(
      'Failed to start Aegis Auth Service',
      'Bootstrap',
      error.stack,
      {
        error: error.message,
        port,
        host,
      }
    );
    process.exit(1);
  }

  process.on('SIGTERM', async () => {
    logger.warn('SIGTERM signal received: closing HTTP server', 'Bootstrap');
    await app.close();
    logger.info('HTTP server closed', 'Bootstrap');
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    logger.warn('SIGINT signal received: closing HTTP server', 'Bootstrap');
    await app.close();
    logger.info('HTTP server closed', 'Bootstrap');
    process.exit(0);
  });

  process.on('unhandledRejection', (reason: any) => {
    logger.error(
      'Unhandled Promise Rejection',
      'Bootstrap',
      reason?.stack || String(reason),
      {
        reason: reason?.message || String(reason),
      }
    );
  });

  process.on('uncaughtException', (error: Error) => {
    logger.error(
      'Uncaught Exception',
      'Bootstrap',
      error.stack,
      {
        error: error.message,
      }
    );
    process.exit(1);
  });

}
bootstrap();
