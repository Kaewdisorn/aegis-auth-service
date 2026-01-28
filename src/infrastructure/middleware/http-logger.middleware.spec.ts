import { HttpLoggerMiddleware } from './http-logger.middleware';
import { ILogger } from '@application/ports/logger.interface';
import { Request, Response } from 'express';

describe('HttpLoggerMiddleware', () => {
    let middleware: HttpLoggerMiddleware;
    let mockLogger: jest.Mocked<ILogger>;
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let nextFunction: jest.Mock;
    let finishCallback: () => void;

    beforeEach(() => {
        mockLogger = {
            info: jest.fn(),
            warn: jest.fn(),
            error: jest.fn(),
            debug: jest.fn(),
        };

        middleware = new HttpLoggerMiddleware(mockLogger);

        mockRequest = {
            method: 'GET',
            originalUrl: '/test',
            ip: '127.0.0.1',
            headers: { 'user-agent': 'test-agent' },
        } as Partial<Request>;

        (mockRequest as any).correlationId = 'test-correlation-id';

        mockResponse = {
            statusCode: 200,
            on: jest.fn((event: string, callback: () => void) => {
                if (event === 'finish') {
                    finishCallback = callback;
                }
                return mockResponse as Response;
            }),
        };

        nextFunction = jest.fn();
    });

    it('should call next()', () => {
        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );

        expect(nextFunction).toHaveBeenCalled();
    });

    it('should register finish event listener', () => {
        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );

        expect(mockResponse.on).toHaveBeenCalledWith('finish', expect.any(Function));
    });

    it('should log info for successful requests (2xx)', () => {
        mockResponse.statusCode = 200;

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );
        finishCallback();

        expect(mockLogger.info).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            expect.objectContaining({
                correlationId: 'test-correlation-id',
                method: 'GET',
                path: '/test',
                statusCode: 200,
                ip: '127.0.0.1',
                userAgent: 'test-agent',
            }),
        );
    });

    it('should log info for 3xx redirects', () => {
        mockResponse.statusCode = 301;

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );
        finishCallback();

        expect(mockLogger.info).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            expect.objectContaining({
                statusCode: 301,
            }),
        );
    });

    it('should log warn for client errors (4xx)', () => {
        mockResponse.statusCode = 404;

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );
        finishCallback();

        expect(mockLogger.warn).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            expect.objectContaining({
                statusCode: 404,
            }),
        );
    });

    it('should log warn for 400 Bad Request', () => {
        mockResponse.statusCode = 400;

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );
        finishCallback();

        expect(mockLogger.warn).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            expect.objectContaining({
                statusCode: 400,
            }),
        );
    });

    it('should log error for server errors (5xx)', () => {
        mockResponse.statusCode = 500;

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );
        finishCallback();

        expect(mockLogger.error).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            undefined,
            expect.objectContaining({
                statusCode: 500,
            }),
        );
    });

    it('should log error for 503 Service Unavailable', () => {
        mockResponse.statusCode = 503;

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );
        finishCallback();

        expect(mockLogger.error).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            undefined,
            expect.objectContaining({
                statusCode: 503,
            }),
        );
    });

    it('should include duration in metadata', () => {
        jest.useFakeTimers();
        const startTime = Date.now();

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );

        jest.advanceTimersByTime(150);
        finishCallback();

        expect(mockLogger.info).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            expect.objectContaining({
                duration: expect.any(Number),
            }),
        );

        const callArgs = mockLogger.info.mock.calls[0];
        const metadata = callArgs[2] as { duration: number };
        expect(metadata.duration).toBeGreaterThanOrEqual(150);

        jest.useRealTimers();
    });

    it('should handle POST requests', () => {
        mockRequest.method = 'POST';
        mockRequest.originalUrl = '/auth/login';

        middleware.use(
            mockRequest as Request,
            mockResponse as Response,
            nextFunction,
        );
        finishCallback();

        expect(mockLogger.info).toHaveBeenCalledWith(
            'HTTP Request',
            'HttpLogger',
            expect.objectContaining({
                method: 'POST',
                path: '/auth/login',
            }),
        );
    });
});
