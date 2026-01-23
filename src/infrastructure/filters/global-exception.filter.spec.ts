import { ILogger } from "../../application/ports/logger.interface";
import { ArgumentsHost, HttpException, HttpStatus } from "@nestjs/common";
import { Request, Response } from "express";

jest.mock('uuid', () => ({
    v4: jest.fn(() => 'mock-uuid-value'),
}));

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
        };

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
        it('should handle HttpException and return correct status code', () => {
            const exception = new HttpException('Not Found', HttpStatus.NOT_FOUND);

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.NOT_FOUND);
            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    statusCode: HttpStatus.NOT_FOUND,
                    message: 'Not Found',
                    error: 'HttpException',
                    path: '/test-url',
                })
            );
        });

        it('should handle generic Error and return 500 status', () => {
            const exception = new Error('Something went wrong');

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
                    message: 'Internal server error',
                    error: 'Error',
                    path: '/test-url',
                })
            );
        });

        it('should log the exception with correct metadata', () => {
            const exception = new HttpException('Bad Request', HttpStatus.BAD_REQUEST);

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.error).toHaveBeenCalledWith(
                expect.stringContaining('Unhandled exception'),
                'GlobalExceptionFilter',
                undefined,
                expect.objectContaining({
                    error: expect.objectContaining({
                        name: 'HttpException',
                        message: 'Bad Request',
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

        it('should generate new correlationId if not present in request', () => {
            const exception = new HttpException('Test', HttpStatus.BAD_REQUEST);

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    correlationId: expect.any(String),
                })
            );
        });

        it('should include user info in log metadata when user is present', () => {
            (mockRequest as any).user = { id: 'user-123', username: 'testuser' };

            const exception = new HttpException('Forbidden', HttpStatus.FORBIDDEN);

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.error).toHaveBeenCalledWith(
                expect.any(String),
                'GlobalExceptionFilter',
                undefined,
                expect.objectContaining({
                    user: {
                        id: 'user-123',
                        username: 'testuser',
                    },
                })
            );
        });

        it('should not include user info in log metadata when user is not present', () => {
            const exception = new HttpException('Test', HttpStatus.BAD_REQUEST);

            filter.catch(exception, mockArgumentsHost);

            expect(mockLogger.error).toHaveBeenCalledWith(
                expect.any(String),
                'GlobalExceptionFilter',
                undefined,
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

        it('should handle HttpException with array message', () => {
            const exception = new HttpException(
                { message: ['error1', 'error2'] },
                HttpStatus.BAD_REQUEST
            );

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: ['error1', 'error2'],
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
                undefined,
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
            const exception = new HttpException('Test', HttpStatus.BAD_REQUEST);

            filter.catch(exception, mockArgumentsHost);

            expect(mockResponse.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    timestamp: expect.any(String),
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

            it('should not sanitize message for 4xx errors', () => {
                const exception = new HttpException('Not Found', HttpStatus.NOT_FOUND);

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Not Found',
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

            it('should show original message for 4xx HttpException errors', () => {
                const exception = new HttpException('Bad Request - invalid input', HttpStatus.BAD_REQUEST);

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Bad Request - invalid input',
                    })
                );
            });

            it('should show original message for 5xx HttpException errors', () => {
                const exception = new HttpException('Service Unavailable', HttpStatus.SERVICE_UNAVAILABLE);

                filter.catch(exception, mockArgumentsHost);

                expect(mockResponse.json).toHaveBeenCalledWith(
                    expect.objectContaining({
                        message: 'Service Unavailable',
                    })
                );
            });
        });
    });
});