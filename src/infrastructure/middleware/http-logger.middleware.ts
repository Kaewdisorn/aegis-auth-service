import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

const colors = {
    reset: '\x1b[0m',
    cyan: '\x1b[36m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    gray: '\x1b[90m',
};

@Injectable()
export class HttpLoggerMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction): void {
        const startTime = Date.now();
        const { method, originalUrl } = req;

        console.log(`\n${colors.cyan}[HTTP] --> ${method} ${originalUrl}${colors.reset}`);

        res.on('finish', () => {
            const duration = Date.now() - startTime;
            const { statusCode } = res;

            const statusColor = statusCode >= 500 ? colors.red
                : statusCode >= 400 ? colors.yellow
                    : colors.green;

            console.log(`${statusColor}[HTTP] <-- ${method} ${originalUrl} ${statusCode}${colors.reset} ${colors.gray}- ${duration}ms${colors.reset}\n`);
        });

        next();
    }
}
