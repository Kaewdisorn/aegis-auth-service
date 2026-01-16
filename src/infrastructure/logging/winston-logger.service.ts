import { Injectable, Logger, LoggerService } from '@nestjs/common';
import { ILogger } from '@application/ports/logger.interface';

@Injectable()
export class NestLoggerService implements ILogger {
    private readonly logger = new Logger();

    info(message: string, context?: string): void {
        this.logger.log(message, context || 'AegisAuthService');
    }

    error(message: string, trace?: string, context?: string): void {
        this.logger.error(message, trace, context || 'AegisAuthService');
    }

    warn(message: string, context?: string): void {
        this.logger.warn(message, context || 'AegisAuthService');
    }

    debug(message: string, context?: string): void {
        this.logger.debug(message, context || 'AegisAuthService');
    }
}
