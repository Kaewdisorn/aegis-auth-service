import { ILogger } from "../../application/ports/logger.interface";
import { ArgumentsHost, HttpException, HttpStatus } from "@nestjs/common";
import { Request, Response } from "express";
import { GlobalExceptionFilter } from "./global-exception.filter";

describe('GlobalExceptionFilter', () => {
    let filter: GlobalExceptionFilter;
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
            method: 'GET',
            url: '/test-url',
            path: '/test-path',
            headers: {
                'user-agent': 'test-agent',
                'content-type': 'application/json',
            },
            query: { foo: 'bar' },
            params: { id: '123' },
            ip: '127.0.0.1',
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

        filter = new GlobalExceptionFilter(mockLogger);
    });

    describe('catch', () => {
        it('should handle any exception and return 500 status code', () => {
            // GlobalExceptionFilter catches ALL unhandled exceptions and returns 500
            // HttpExceptions are handled by HttpExceptionFilter
            const exception = new Error('Something unexpected');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
                    error: 'Error',
                    path: '/test-url',
                    correlationId: 'test-correlation-id',
                })
            );
        });

        it('should handle generic Error and return 500 status with correlationId', () => {
            const exception = new Error('Something went wrong');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
                    error: 'Error',
                    path: '/test-url',
                    correlationId: 'test-correlation-id',
                })
            );
        });

        it('should log the exception with correct metadata', () => {
            const exception = new Error('Something went wrong');

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.error).toHaveBeenCalledWith(
                expect.stringContaining('Unhandled exception'),
                'GlobalExceptionFilter',
                expect.any(String), // stack trace
                expect.objectContaining({
                    correlationId: 'test-correlation-id',
                    error: expect.objectContaining({
                        name: 'Error',
                        message: 'Something went wrong',
                    }),
                    request: expect.objectContaining({
                        method: 'GET',
                        url: '/test-url',
                        path: '/test-path',
                        ip: '127.0.0.1',
                        userAgent: 'test-agent',
                    }),
                })
            );
        });

        it('should use existing correlationId from request if available', () => {
            const correlationId = 'existing-correlation-id';
            (mockRequest as any).correlationId = correlationId;

            const exception = new HttpException('Test', HttpStatus.BAD_REQUEST);

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    correlationId,
                })
            );
        });

        it('should use correlationId from request (set by middleware)', () => {
            const exception = new Error('Test error');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    correlationId: 'test-correlation-id',
                })
            );
        });

        it('should include user info in log metadata when user is present', () => {
            (mockRequest as any).user = { id: 'user-123', username: 'testuser' };

            const exception = new Error('Database error');

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.error).toHaveBeenCalledWith(
                expect.any(String),
                'GlobalExceptionFilter',
                expect.any(String), // stack trace
                expect.objectContaining({
                    user: {
                        id: 'user-123',
                        username: 'testuser',
                    },
                })
            );
        });

        it('should not include user info in log metadata when user is not present', () => {
            const exception = new Error('Test error');

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.error).toHaveBeenCalledWith(
                expect.any(String),
                'GlobalExceptionFilter',
                expect.any(String), // stack trace
                expect.objectContaining({
                    user: undefined,
                })
            );
        });

        it('should handle HttpException with object response containing message', () => {
            const exception = new HttpException(
                { message: 'Validation failed', errors: ['field is required'] },
                HttpStatus.BAD_REQUEST
            );

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: 'Validation failed',
                })
            );
        });

        it('should handle exception with proper error name', () => {
            class CustomError extends Error {
                constructor(message: string) {
                    super(message);
                    this.name = 'CustomError';
                }
            }
            const exception = new CustomError('Custom error occurred');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: 'CustomError',
                    correlationId: 'test-correlation-id',
                })
            );
        });

        it('should sanitize sensitive headers in log metadata', () => {
            mockRequest.headers = {
                'authorization': 'Bearer secret-token',
                'cookie': 'session=secret',
                'x-api-key': 'api-key-value',
                'x-auth-token': 'auth-token-value',
                'content-type': 'application/json',
            };

            const exception = new Error('Test error');

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.error).toHaveBeenCalledWith(
                expect.any(String),
                'GlobalExceptionFilter',
                expect.any(String), // stack trace
                expect.objectContaining({
                    request: expect.objectContaining({
                        headers: {
                            'authorization': '[REDACTED]',
                            'cookie': '[REDACTED]',
                            'x-api-key': '[REDACTED]',
                            'x-auth-token': '[REDACTED]',
                            'content-type': 'application/json',
                        },
                    }),
                })
            );
        });

        it('should include timestamp in response', () => {
            const exception = new Error('Test error');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    timestamp: expect.any(String),
                    correlationId: 'test-correlation-id',
                })
            );
        });

        describe('in production environment', () => {
            const originalNodeEnv = process.env.NODE_ENV;

            beforeEach(() => {
                process.env.NODE_ENV = 'production';
            });

            afterEach(() => {
                process.env.NODE_ENV = originalNodeEnv;
            });

            it('should sanitize message for 5xx errors', () => {
                const exception = new Error('Database connection failed');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Internal server error',
                    })
                );
            });

            it('should always return 500 for unhandled exceptions', () => {
                // GlobalExceptionFilter only handles unhandled exceptions
                // HttpExceptions should be caught by HttpExceptionFilter
                const exception = new Error('Unexpected error');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Internal server error',
                        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
                    })
                );
            });
        });

        describe('in non-production environment', () => {
            const originalNodeEnv = process.env.NODE_ENV;

            beforeEach(() => {
                process.env.NODE_ENV = 'development';
            });

            afterEach(() => {
                process.env.NODE_ENV = originalNodeEnv;
            });

            it('should show original message for generic errors in development', () => {
                const exception = new Error('Database connection failed');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Database connection failed',
                    })
                );
            });

            it('should show original message for any error in development', () => {
                const exception = new Error('Service unavailable - downstream failure');

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Service unavailable - downstream failure',
                    })
                );
            });
        });
    });
});