import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ILogger } from '@application/ports/logger.interface';
import { GlobalExceptionFilter } from '@infrastructure/filters/global-exception.filter';
import { HttpExceptionFilter } from '@infrastructure/filters/http-exception.filter';
import { ServerConfig } from '@infrastructure/config/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: false,
  });
  const logger = app.get<ILogger>(ILogger);
  const serverConfig = app.get<ServerConfig>(ServerConfig);

  logger.info('Starting Aegis Auth Service...', 'Bootstrap', {
    environment: serverConfig.serverConfig.nodeEnv,
    nodeVersion: process.version,
    pid: process.pid,
  });

  app.useGlobalFilters(
    new GlobalExceptionFilter(logger),  // Lower priority - catches non-HTTP exceptions
    new HttpExceptionFilter(logger),    // Higher priority - catches HttpException first
  );

  try {
    await app.listen(serverConfig.serverConfig.port);

    logger.info(`Aegis Auth Service started successfully`, 'Bootstrap', {
      url: `http://${serverConfig.serverConfig.host}:${serverConfig.serverConfig.port}`,
      environment: serverConfig.serverConfig.nodeEnv,
      port: serverConfig.serverConfig.port,
      host: serverConfig.serverConfig.host,
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
        port: serverConfig.serverConfig.port,
        host: serverConfig.serverConfig.host,
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
