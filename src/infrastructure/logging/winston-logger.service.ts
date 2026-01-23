import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ILogger, LogMetadata } from '@application/ports/logger.interface';
import * as winston from 'winston';
import * as os from 'os';
import DailyRotateFile from 'winston-daily-rotate-file';

@Injectable()
export class WinstonLoggerService implements ILogger {
    private readonly logger: winston.Logger;
    private readonly sensitiveFields = [
        'password',
        'token',
        'accessToken',
        'refreshToken',
        'authorization',
        'cookie',
        'secret',
        'apiKey',
        'creditCard',
        'ssn',
    ];

    constructor(private readonly configService: ConfigService) {
        const level = this.configService.get<string>('LOG_LEVEL') || 'info';
        const nodeEnv = this.configService.get<string>('NODE_ENV') || 'development';
        const isProduction = nodeEnv === 'production';

        const baseFormat = winston.format.combine(
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
            winston.format.errors({ stack: true }),
        );

        // Dev format
        const devConsoleFormat = winston.format.combine(
            baseFormat,
            winston.format.colorize({ level: true }),
            winston.format.printf(({ timestamp, level, message, context, trace, ...meta }) => {
                const ctx = context || 'App';
                const traceStr = trace ? `\n${trace}` : '';
                const cleanMeta = this.sanitizeMetadata(meta);
                const metaStr = Object.keys(cleanMeta).length > 0
                    ? `\n${JSON.stringify(cleanMeta, null, 2)}`
                    : '';
                return `${timestamp} [${level}] [${ctx}] ${message}${metaStr}${traceStr}`;
            }),
        );

        // Production format
        const prodFormat = winston.format.combine(
            baseFormat,
            winston.format.json(),
        );

        const transports: winston.transport[] = [];

        if (isProduction) {
            transports.push(
                new winston.transports.Console({
                    format: prodFormat,
                }),
            );

            transports.push(
                new DailyRotateFile({
                    filename: 'logs/app-%DATE%.json',
                    datePattern: 'YYYY-MM-DD',
                    maxSize: '20m',
                    maxFiles: '14d',
                    format: prodFormat,
                }),
            );

            transports.push(
                new DailyRotateFile({
                    filename: 'logs/error-%DATE%.json',
                    datePattern: 'YYYY-MM-DD',
                    level: 'error',
                    maxSize: '20m',
                    maxFiles: '30d',
                    format: prodFormat,
                }),
            );
        }

        transports.push(
            new winston.transports.Console({
                format: devConsoleFormat,
            }),
        );

        this.logger = winston.createLogger({
            level,
            transports,
        });

    }

    private sanitizeMetadata(metadata: any): any {
        if (!metadata || typeof metadata !== 'object') {
            return metadata;
        }

        if (Array.isArray(metadata)) {
            return metadata.map(item => this.sanitizeMetadata(item));
        }

        const sanitized: any = {};
        for (const [key, value] of Object.entries(metadata)) {
            const lowerKey = key.toLowerCase();
            const isSensitive = this.sensitiveFields.some(field =>
                lowerKey.includes(field.toLowerCase())
            );

            if (isSensitive) {
                sanitized[key] = '***REDACTED***';
            } else if (value && typeof value === 'object') {
                sanitized[key] = this.sanitizeMetadata(value);
            } else {
                sanitized[key] = value;
            }
        }

        return sanitized;
    }

    private enrichMetadata(metadata?: LogMetadata): LogMetadata {
        const enriched: LogMetadata = {
            ...metadata,
            environment: this.configService.get<string>('NODE_ENV') || 'development',
            serviceName: 'aegis-auth-service',
            hostname: process.env.HOSTNAME || os.hostname() || 'unknown',
            pid: process.pid,
        };

        return this.sanitizeMetadata(enriched);
    }

    info(message: string, context?: string, metadata?: LogMetadata): void {
        const enrichedMeta = metadata ? this.enrichMetadata(metadata) : {};
        this.logger.info(message, { context, ...enrichedMeta });
    }

    error(message: string, context?: string, trace?: string, metadata?: LogMetadata): void {
        const enrichedMeta = metadata ? this.enrichMetadata(metadata) : {};
        this.logger.error(message, { context, trace, ...enrichedMeta });
    }

    warn(message: string, context?: string, metadata?: LogMetadata): void {
        const enrichedMeta = metadata ? this.enrichMetadata(metadata) : {};
        this.logger.warn(message, { context, ...enrichedMeta });
    }

    debug(message: string, context?: string, metadata?: LogMetadata): void {
        const enrichedMeta = metadata ? this.enrichMetadata(metadata) : {};
        this.logger.debug(message, { context, ...enrichedMeta });
    }


}