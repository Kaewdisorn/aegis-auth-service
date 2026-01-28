import { ILogger } from '@application/ports/logger.interface';
import { Request, Response } from 'express';
import {
    ExceptionFilter,
    Catch,
    HttpException,
    ArgumentsHost,
} from '@nestjs/common';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
    constructor(private readonly logger: ILogger) { }

    catch(exception: HttpException, host: ArgumentsHost): void {
        const ctx = host.switchToHttp();
        const request = ctx.getRequest<Request>();
        const response = ctx.getResponse<Response>();
        const statusCode = exception.getStatus();
        const exceptionResponse = exception.getResponse();
        const timestamp = new Date().toISOString();
        const correlationId = (request as any).correlationId;

        const message =
            typeof exceptionResponse === 'string'
                ? exceptionResponse
                : (exceptionResponse as any).message || exception.message;

        const logMetadata = {
            statusCode,
            path: request.url,
            method: request.method,
            correlationId,
            ip: request.ip,
            userAgent: request.headers['user-agent'],
        };

        if (statusCode >= 500) {
            this.logger.error(
                `HTTP Exception: ${message}`,
                'HttpExceptionFilter',
                exception.stack,
                logMetadata,
            );
        } else {
            this.logger.warn(
                `HTTP Exception: ${message}`,
                'HttpExceptionFilter',
                logMetadata,
            );
        }

        response.status(statusCode).json({
            statusCode,
            message,
            error: exception.name,
            correlationId,
            timestamp,
            path: request.url,
        });

    }
}