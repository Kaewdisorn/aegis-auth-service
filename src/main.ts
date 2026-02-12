import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ILogger } from '@application/ports/logger.interface';
import { GlobalExceptionFilter } from '@infrastructure/filters/global-exception.filter';
import { HttpExceptionFilter } from '@infrastructure/filters/http-exception.filter';
import { DomainExceptionFilter } from '@infrastructure/filters/domain-exception.filter';
import { IAppConfig } from '@application/ports/config.interface';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: false,
  });

  const config = app.get<IAppConfig>(IAppConfig);
  const logger = app.get<ILogger>(ILogger);

  app.useGlobalFilters(
    new GlobalExceptionFilter(logger),  // Lowest priority - catches unhandled exceptions
    new DomainExceptionFilter(logger),  // Mid priority - catches domain validation errors
    new HttpExceptionFilter(logger),    // Highest priority - catches HttpException first
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  try {
    await app.listen(config.appConfig.port);

    logger.info(`🚀 Aegis Auth Service started successfully`, 'Bootstrap', {
      url: `http://${config.appConfig.host}:${config.appConfig.port}`,
      host: config.appConfig.host,
      port: config.appConfig.port,
      environment: config.appConfig.nodeEnv,
      nodeVersion: process.version,
      pid: process.pid,
    });

    // logger.info('Starting Aegis Auth Service...', 'Bootstrap', {
    //   environment: config.appConfig.nodeEnv,
    //   nodeVersion: process.version,
    //   pid: process.pid,
    // });

    // logger.info('Service health check passed', 'Bootstrap', {
    //   status: 'healthy',
    //   uptime: process.uptime(),
    // });

  } catch (error) {
    logger.error(
      'Failed to start Aegis Auth Service',
      'Bootstrap',
      error.stack,
      {
        error: error.message,
        port: config.appConfig.port,
        host: config.appConfig.host,
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
