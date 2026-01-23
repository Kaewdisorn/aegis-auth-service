import { ILogger } from '@application/ports/logger.interface';
import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {

    constructor(private readonly logger: ILogger) { }

    catch(exception: Error, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>();

        const correlationId = (request as any).correlationId || uuidv4();

        const status =
            exception instanceof HttpException
                ? exception.getStatus()
                : HttpStatus.INTERNAL_SERVER_ERROR;

        const message =
            exception instanceof HttpException
                ? exception.message
                : 'Internal server error';

        this.logger.error(
            `Unhandled exception: ${exception.message}`,
            'GlobalExceptionFilter',
            exception.stack || '',
            {
                correlationId,
                // error: {
                //     name: exception.name,
                //     message: exception.message,
                //     stack: exception.stack,
                // },
                request: {
                    method: request.method,
                    url: request.url,
                    path: request.path,
                    headers: this.sanitizeHeaders(request.headers),
                    query: request.query,
                    params: request.params,
                    ip: request.ip,
                    userAgent: request.headers['user-agent'],
                },
                user: (request as any).user
                    ? {
                        id: (request as any).user.id,
                        username: (request as any).user.username,
                    }
                    : undefined,
                timestamp: new Date().toISOString(),
            },
        );

        const errorResponse = {
            statusCode: status,
            message:
                process.env.NODE_ENV === 'production'
                    ? message
                    : exception.message || message,
            error: exception.name || 'Error',
            correlationId,
            timestamp: new Date().toISOString(),
            path: request.url,
            // ...(process.env.NODE_ENV !== 'production' && {
            //     //stack: exception.stack,
            //     stack: this.parseStack(exception.stack),
            // }),
        };

        response.status(status).json(errorResponse);
    }

    private sanitizeHeaders(headers: any): any {
        const sanitized = { ...headers };
        const sensitiveHeaders = [
            'authorization',
            'cookie',
            'x-api-key',
            'x-auth-token',
        ];

        sensitiveHeaders.forEach((header) => {
            if (sanitized[header]) {
                sanitized[header] = '[REDACTED]';
            }
        });

        return sanitized;
    }
}