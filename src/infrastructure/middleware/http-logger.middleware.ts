import { ILogger } from '@application/ports/logger.interface';
import { Inject, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';


export class HttpLoggerMiddleware implements NestMiddleware {
    constructor(@Inject(ILogger) private readonly logger: ILogger) { }

    use(req: Request, res: Response, next: NextFunction) {
        console.log(`${req.method} ${req.originalUrl}`);
        this.logger.info(`[${req.method}] ${req.originalUrl}`, 'HttpLoggerMiddleware');
        next();
    }
}