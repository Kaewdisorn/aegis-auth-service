import { Inject, Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ILogger } from '@application/ports/logger.interface';

@Injectable()
export class HttpLoggerMiddleware implements NestMiddleware {
    constructor(@Inject(ILogger) private readonly logger: ILogger) { }

    use(req: Request, res: Response, next: NextFunction): void {
        const startTime = Date.now();
        const { method, originalUrl, ip } = req;
        const correlationId = req['correlationId'] as string;
        const userAgent = req.headers['user-agent'];

        res.on('finish', () => {
            const duration = Date.now() - startTime;
            const { statusCode } = res;

            const metadata = {
                correlationId,
                method,
                path: originalUrl,
                statusCode,
                duration,
                ip,
                userAgent,
            };

            if (statusCode >= 500) {
                this.logger.error('HTTP Request', 'HttpLogger', undefined, metadata);
            } else if (statusCode >= 400) {
                this.logger.warn('HTTP Request', 'HttpLogger', metadata);
            } else {
                this.logger.info('HTTP Request', 'HttpLogger', metadata);
            }
        });

        next();
    }
}
