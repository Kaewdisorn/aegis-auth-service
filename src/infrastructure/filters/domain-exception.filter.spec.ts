import { DomainExceptionFilter } from './domain-exception.filter';
import { DomainValidationException } from '@domain/exceptions/domain-validation.exception';
import { ILogger } from '@application/ports/logger.interface';
import { ArgumentsHost, HttpStatus } from '@nestjs/common';
import { Request, Response } from 'express';

describe('DomainExceptionFilter', () => {
    let filter: DomainExceptionFilter;
    let mockLogger: jest.Mocked<ILogger>;
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockArgumentsHost: jest.Mocked<ArgumentsHost>;

    beforeEach(() => {
        mockLogger = {
            info: jest.fn(),
            error: jest.fn(),
            warn: jest.fn(),
            debug: jest.fn(),
        };

        mockRequest = {
            method: 'POST',
            url: '/auth/register',
            path: '/auth/register',
            headers: {
                'user-agent': 'Mozilla/5.0',
                'content-type': 'application/json',
            },
            query: {},
            params: {},
            ip: '192.168.1.1',
            correlationId: 'test-correlation-id',
        } as Partial<Request> & { correlationId: string };

        mockResponse = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
        };

        mockArgumentsHost = {
            switchToHttp: jest.fn().mockReturnValue({
                getRequest: jest.fn().mockReturnValue(mockRequest),
                getResponse: jest.fn().mockReturnValue(mockResponse),
            }),
            getArgs: jest.fn(),
            getArgByIndex: jest.fn(),
            switchToRpc: jest.fn(),
            switchToWs: jest.fn(),
            getType: jest.fn(),
        };

        filter = new DomainExceptionFilter(mockLogger);
    });

    describe('catch', () => {
        it('should return 400 status for a single validation error', () => {
            const exception = new DomainValidationException('Invalid email format');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    statusCode: HttpStatus.BAD_REQUEST,
                    message: ['Invalid email format'],
                    error: 'Bad Request',
                    correlationId: 'test-correlation-id',
                    path: '/auth/register',
                }),
            );
        });

        it('should return 400 status with multiple validation errors', () => {
            const errors = [
                'Password must be at least 8 characters',
                'Password must contain at least one uppercase letter',
                'Password must contain at least one number',
            ];
            const exception = new DomainValidationException(errors);

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    statusCode: HttpStatus.BAD_REQUEST,
                    message: errors,
                    error: 'Bad Request',
                }),
            );
        });

        it('should include timestamp in the response', () => {
            const exception = new DomainValidationException('Invalid email format');

            filter.catch(exception, mockArgumentsHost);

            const responseBody = (mockResponse.json as jest.Mock).mock.calls[0][0];
            expect(responseBody.timestamp).toBeDefined();
            expect(() => new Date(responseBody.timestamp)).not.toThrow();
        });

        it('should include correlationId from request', () => {
            (mockRequest as any).correlationId = 'custom-correlation-id';
            const exception = new DomainValidationException('Invalid email format');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    correlationId: 'custom-correlation-id',
                }),
            );
        });

        it('should handle missing correlationId gracefully', () => {
            delete (mockRequest as any).correlationId;
            const exception = new DomainValidationException('Invalid email format');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    statusCode: HttpStatus.BAD_REQUEST,
                    correlationId: undefined,
                }),
            );
        });
    });

    describe('logging', () => {
        it('should log at warn level for domain validation errors', () => {
            const exception = new DomainValidationException('Invalid email format');

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.warn).toHaveBeenCalledWith(
                'Domain validation error: Invalid email format',
                'DomainExceptionFilter',
                expect.objectContaining({
                    correlationId: 'test-correlation-id',
                    errors: ['Invalid email format'],
                    path: '/auth/register',
                    method: 'POST',
                }),
            );
            expect(mockLogger.error).not.toHaveBeenCalled();
        });

        it('should log all errors in metadata for multiple validation errors', () => {
            const errors = [
                'Password must be at least 8 characters',
                'Password must contain at least one uppercase letter',
            ];
            const exception = new DomainValidationException(errors);

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.warn).toHaveBeenCalledWith(
                expect.stringContaining('Password must be at least 8 characters'),
                'DomainExceptionFilter',
                expect.objectContaining({
                    errors,
                }),
            );
        });

        it('should include request method and path in log metadata', () => {
            const exception = new DomainValidationException('Some error');

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.warn).toHaveBeenCalledWith(
                expect.any(String),
                'DomainExceptionFilter',
                expect.objectContaining({
                    method: 'POST',
                    path: '/auth/register',
                }),
            );
        });
    });
});
