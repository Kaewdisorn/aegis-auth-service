import { Injectable } from '@nestjs/common';
import { ILogger } from '@application/ports/logger.interface';
import * as winston from 'winston';

@Injectable()
export class WinstonLoggerService implements ILogger {
    private readonly logger: winston.Logger;

    constructor() {
        this.logger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: winston.format.combine(
                winston.format.timestamp({ format: 'MM/DD/YYYY, h:mm:ss A' }),
                winston.format.errors({ stack: true }),
            ),
            transports: [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.colorize(),
                        winston.format.printf(({ timestamp, level, message, context, trace }) => {
                            const ctx = context || 'AegisAuthService';
                            const traceStr = trace ? `\n${trace}` : '';
                            return `[Nest] ${process.pid}  - ${timestamp}     ${level} [${ctx}] ${message}${traceStr}`;
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

    info(message: string, context?: string): void {
        this.logger.info(message, { context });
    }

    error(message: string, trace?: string, context?: string): void {
        this.logger.error(message, { context, trace });
    }

    warn(message: string, context?: string): void {
        this.logger.warn(message, { context });
    }

    debug(message: string, context?: string): void {
        this.logger.debug(message, { context });
    }

}
