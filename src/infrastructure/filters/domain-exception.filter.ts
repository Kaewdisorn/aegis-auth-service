import { ILogger } from '@application/ports/logger.interface';
import { DomainValidationException } from '@domain/exceptions/domain-validation.exception';
import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(DomainValidationException)
export class DomainExceptionFilter implements ExceptionFilter {

    constructor(private readonly logger: ILogger) { }

    catch(exception: DomainValidationException, host: ArgumentsHost): void {
        const ctx = host.switchToHttp();
        const request = ctx.getRequest<Request>();
        const response = ctx.getResponse<Response>();
        const correlationId = (request as any).correlationId;
        const timestamp = new Date().toISOString();
        const status = HttpStatus.BAD_REQUEST;

        this.logger.warn(
            `Domain validation error: ${exception.message}`,
            'DomainExceptionFilter',
            {
                correlationId,
                errors: exception.errors,
                path: request.url,
                method: request.method,
            },
        );

        response.status(status).json({
            statusCode: status,
            message: exception.errors,
            error: 'Bad Request',
            correlationId,
            timestamp,
            path: request.url,
        });
    }
}
