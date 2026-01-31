import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class HttpLoggerMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction): void {
        const startTime = Date.now();
        const { method, originalUrl } = req;

        res.on('finish', () => {
            const duration = Date.now() - startTime;
            const { statusCode } = res;

            console.log(`[HTTP] ${method} ${originalUrl} ${statusCode} - ${duration}ms`);
        });

        next();
    }
}
