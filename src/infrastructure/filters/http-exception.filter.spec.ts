import { HttpExceptionFilter } from './http-exception.filter';
import { ILogger } from '@application/ports/logger.interface';
import {
    ArgumentsHost,
    HttpException,
    HttpStatus,
    BadRequestException,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    InternalServerErrorException,
} from '@nestjs/common';
import { Request, Response } from 'express';

describe('HttpExceptionFilter', () => {
    let filter: HttpExceptionFilter;
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
            url: '/api/auth/login',
            path: '/api/auth/login',
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

        filter = new HttpExceptionFilter(mockLogger);
    });

    describe('catch', () => {
        describe('4xx Client Errors - should log at warn level', () => {
            it('should handle BadRequestException (400)', () => {
                const exception = new BadRequestException('Invalid input');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalledWith(
                    'HTTP Exception: Invalid input',
                    'HttpExceptionFilter',
                    expect.objectContaining({
                        statusCode: 400,
                    }),
                );
                expect(mockLogger.error).not.toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(400);
                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        statusCode: 400,
                        message: 'Invalid input',
                        error: 'BadRequestException',
                    }),
                );
            });

            it('should handle UnauthorizedException (401)', () => {
                const exception = new UnauthorizedException('Invalid credentials');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalled();
                expect(mockLogger.error).not.toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(401);
                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        statusCode: 401,
                        error: 'UnauthorizedException',
                    }),
                );
            });

            it('should handle ForbiddenException (403)', () => {
                const exception = new ForbiddenException('Access denied');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalled();
                expect(mockLogger.error).not.toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(403);
            });

            it('should handle NotFoundException (404)', () => {
                const exception = new NotFoundException('Resource not found');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalled();
                expect(mockLogger.error).not.toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(404);
            });

            it('should handle custom 422 Unprocessable Entity', () => {
                const exception = new HttpException('Validation failed', HttpStatus.UNPROCESSABLE_ENTITY);

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(422);
            });

            it('should handle 429 Too Many Requests', () => {
                const exception = new HttpException('Rate limit exceeded', HttpStatus.TOO_MANY_REQUESTS);

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(429);
            });
        });

        describe('5xx Server Errors - should log at error level', () => {
            it('should handle InternalServerErrorException (500)', () => {
                const exception = new InternalServerErrorException('Server error');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.error).toHaveBeenCalledWith(
                    expect.stringContaining('HTTP Exception'),
                    'HttpExceptionFilter',
                    expect.any(String), // stack trace
                    expect.objectContaining({
                        statusCode: 500,
                    }),
                );
                expect(mockLogger.warn).not.toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(500);
            });

            it('should handle custom 502 Bad Gateway', () => {
                const exception = new HttpException('Bad Gateway', HttpStatus.BAD_GATEWAY);

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.error).toHaveBeenCalled();
                expect(mockLogger.warn).not.toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(502);
            });

            it('should handle custom 503 Service Unavailable', () => {
                const exception = new HttpException('Service Unavailable', HttpStatus.SERVICE_UNAVAILABLE);

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.error).toHaveBeenCalled();
                expect(mockLogger.warn).not.toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(503);
            });

            it('should handle custom 504 Gateway Timeout', () => {
                const exception = new HttpException('Gateway Timeout', HttpStatus.GATEWAY_TIMEOUT);

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.error).toHaveBeenCalled();
                expect(mockResponse.status).toHaveBeenCalledWith(504);
            });

            it('should include stack trace for 5xx errors', () => {
                const exception = new InternalServerErrorException('Server error');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.error).toHaveBeenCalledWith(
                    expect.any(String),
                    'HttpExceptionFilter',
                    exception.stack,
                    expect.any(Object),
                );
            });
        });

        describe('Message parsing', () => {
            it('should handle string response', () => {
                const exception = new HttpException('Simple message', 400);

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Simple message',
                    }),
                );
            });

            it('should handle object response with message', () => {
                const exception = new HttpException(
                    { message: 'Object message', statusCode: 400 },
                    400,
                );

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Object message',
                    }),
                );
            });

            it('should handle validation errors (array of messages)', () => {
                const exception = new BadRequestException({
                    message: ['email must be valid', 'password is required'],
                    error: 'Bad Request',
                });

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: ['email must be valid', 'password is required'],
                    }),
                );
            });

            it('should use exception.message as fallback', () => {
                const exception = new HttpException({ statusCode: 400 }, 400);

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: expect.anything(),
                    }),
                );
            });
        });

        describe('Response format', () => {
            it('should include all required fields in response', () => {
                const exception = new BadRequestException('Test error');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        statusCode: expect.any(Number),
                        message: expect.anything(),
                        error: expect.any(String),
                        correlationId: expect.any(String),
                        timestamp: expect.any(String),
                        path: expect.any(String),
                    }),
                );
            });

            it('should use correlationId from request if available', () => {
                (mockRequest as any).correlationId = 'test-correlation-id';
                const exception = new BadRequestException('Test');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        correlationId: 'test-correlation-id',
                    }),
                );
            });

            it('should use correlationId from request (set by middleware)', () => {
                const exception = new BadRequestException('Test');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        correlationId: 'test-correlation-id',
                    }),
                );
            });

            it('should include timestamp in ISO format', () => {
                const exception = new BadRequestException('Test');

                filter.catch(exception, mockArgumentsHost);

                const jsonCall = (mockResponse.json as jest.Mock).mock.calls[0][0];
                expect(new Date(jsonCall.timestamp).toISOString()).toBe(jsonCall.timestamp);
            });

            it('should include request path', () => {
                const exception = new BadRequestException('Test');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        path: '/api/auth/login',
                    }),
                );
            });
        });

        describe('Log metadata', () => {
            it('should include request context in log metadata', () => {
                const exception = new BadRequestException('Test');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalledWith(
                    expect.any(String),
                    'HttpExceptionFilter',
                    expect.objectContaining({
                        statusCode: 400,
                        path: '/api/auth/login',
                        method: 'POST',
                        ip: '192.168.1.1',
                        userAgent: 'Mozilla/5.0',
                    }),
                );
            });

            it('should include correlationId in log metadata', () => {
                (mockRequest as any).correlationId = 'log-correlation-id';
                const exception = new BadRequestException('Test');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalledWith(
                    expect.any(String),
                    'HttpExceptionFilter',
                    expect.objectContaining({
                        correlationId: 'log-correlation-id',
                    }),
                );
            });

            it('should include message in log message (not metadata)', () => {
                const exception = new BadRequestException('Specific error message');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalledWith(
                    'HTTP Exception: Specific error message',
                    'HttpExceptionFilter',
                    expect.objectContaining({
                        statusCode: 400,
                    }),
                );
            });
        });

        describe('Different HTTP methods', () => {
            it('should handle GET requests', () => {
                mockRequest.method = 'GET';
                mockRequest.url = '/api/users/123';
                const exception = new NotFoundException('User not found');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalledWith(
                    expect.any(String),
                    'HttpExceptionFilter',
                    expect.objectContaining({
                        method: 'GET',
                        path: '/api/users/123',
                    }),
                );
            });

            it('should handle DELETE requests', () => {
                mockRequest.method = 'DELETE';
                const exception = new ForbiddenException('Cannot delete');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalledWith(
                    expect.any(String),
                    'HttpExceptionFilter',
                    expect.objectContaining({
                        method: 'DELETE',
                    }),
                );
            });

            it('should handle PUT requests', () => {
                mockRequest.method = 'PUT';
                const exception = new BadRequestException('Invalid update');

                filter.catch(exception, mockArgumentsHost);

                expect(mockLogger.warn).toHaveBeenCalledWith(
                    expect.any(String),
                    'HttpExceptionFilter',
                    expect.objectContaining({
                        method: 'PUT',
                    }),
                );
            });
        });
    });
});
