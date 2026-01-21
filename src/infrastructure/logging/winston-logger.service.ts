import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ILogger, LogMetadata } from '@application/ports/logger.interface';
import * as winston from 'winston';

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

        this.logger = winston.createLogger({
            level: level,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
            ),
            transports: [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize({ level: true }),
                        winston.format.printf(({ timestamp, level, message, context, trace, ...meta }) => {
                            const ctx = context || 'AegisAuthService';
                            const traceStr = trace ? `\n${trace}` : '';
                            const metaStr = Object.keys(meta).length > 0
                                ? `\n${JSON.stringify(this.sanitizeMetadata(meta), null, 2)}`
                                : '';
                            return `${timestamp} [${level}] [${ctx}] ${message}${metaStr}${traceStr}`;
                        }),
                    ),
                }),
            ],
        });

        // // Add file transports for production
        // if (process.env.NODE_ENV === 'production') {
        //     this.logger.add(
        //         new winston.transports.File({
        //             filename: 'logs/error.log',
        //             level: 'error',
        //             maxsize: 5242880, // 5MB
        //             maxFiles: 5,
        //             format: winston.format.json(),
        //         }),
        //     );
        //     this.logger.add(
        //         new winston.transports.File({
        //             filename: 'logs/combined.log',
        //             maxsize: 5242880,
        //             maxFiles: 5,
        //             format: winston.format.json(),
        //         }),
        //     );
        // }
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

            // Check if the key contains sensitive information
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
            hostname: process.env.HOSTNAME || 'unknown',
            pid: process.pid,
        };

        return this.sanitizeMetadata(enriched);
    }

    info(message: string, context?: string, metadata?: LogMetadata): void {
        const enrichedMeta = metadata ? this.enrichMetadata(metadata) : {};
        this.logger.info(message, { context, ...enrichedMeta });
    }

    error(message: string, trace?: string, context?: string, metadata?: LogMetadata): void {
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