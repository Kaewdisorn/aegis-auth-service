import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { WinstonLoggerService } from './winston-logger.service';
import * as winston from 'winston';

jest.mock('winston', () => {
    const mockLogger = {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
        add: jest.fn(),
    };

    return {
        createLogger: jest.fn(() => mockLogger),
        format: {
            combine: jest.fn(),
            timestamp: jest.fn(),
            errors: jest.fn(),
            colorize: jest.fn(),
            printf: jest.fn(),
            json: jest.fn(),
        },
        transports: {
            Console: jest.fn(),
            File: jest.fn(),
        },
    };
});

describe('WinstonLoggerService', () => {
    let service: WinstonLoggerService;
    let configService: ConfigService;
    let mockWinstonLogger: any;

    beforeEach(async () => {
        // Reset mocks
        jest.clearAllMocks();

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                WinstonLoggerService,
                {
                    provide: ConfigService,
                    useValue: {
                        get: jest.fn((key: string) => {
                            if (key === 'LOG_LEVEL') return 'debug';
                            return undefined;
                        }),
                    },
                },
            ],
        }).compile();

        service = module.get<WinstonLoggerService>(WinstonLoggerService);
        configService = module.get<ConfigService>(ConfigService);
        mockWinstonLogger = (winston.createLogger as jest.Mock).mock.results[0].value;
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('constructor', () => {
        it('should create winston logger with configured log level', () => {
            expect(winston.createLogger).toHaveBeenCalled();
            expect(configService.get).toHaveBeenCalledWith('LOG_LEVEL');
        });

        it('should use "info" as default log level when LOG_LEVEL is not set', async () => {
            jest.clearAllMocks();

            const module: TestingModule = await Test.createTestingModule({
                providers: [
                    WinstonLoggerService,
                    {
                        provide: ConfigService,
                        useValue: {
                            get: jest.fn(() => undefined),
                        },
                    },
                ],
            }).compile();

            const newService = module.get<WinstonLoggerService>(WinstonLoggerService);

            expect(newService).toBeDefined();
            expect(winston.createLogger).toHaveBeenCalledWith(
                expect.objectContaining({
                    level: 'info',
                }),
            );
        });

        it('should configure Console transport', () => {
            expect(winston.transports.Console).toHaveBeenCalled();
        });
    });

    describe('info', () => {
        it('should call winston logger info method with message', () => {
            const message = 'Test info message';

            service.info(message);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(message, { context: undefined });
        });

        it('should call winston logger info method with message and context', () => {
            const message = 'Test info message';
            const context = 'TestContext';

            service.info(message, context);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(message, { context });
        });
    });

    describe('error', () => {
        it('should call winston logger error method with message', () => {
            const message = 'Test error message';

            service.error(message);

            expect(mockWinstonLogger.error).toHaveBeenCalledWith(message, {
                context: undefined,
                trace: undefined,
            });
        });

        it('should call winston logger error method with message and trace', () => {
            const message = 'Test error message';
            const trace = 'Error stack trace';

            service.error(message, trace);

            expect(mockWinstonLogger.error).toHaveBeenCalledWith(message, {
                context: undefined,
                trace,
            });
        });

        it('should call winston logger error method with message, trace and context', () => {
            const message = 'Test error message';
            const trace = 'Error stack trace';
            const context = 'ErrorContext';

            service.error(message, trace, context);

            expect(mockWinstonLogger.error).toHaveBeenCalledWith(message, {
                context,
                trace,
            });
        });
    });

    describe('warn', () => {
        it('should call winston logger warn method with message', () => {
            const message = 'Test warning message';

            service.warn(message);

            expect(mockWinstonLogger.warn).toHaveBeenCalledWith(message, { context: undefined });
        });

        it('should call winston logger warn method with message and context', () => {
            const message = 'Test warning message';
            const context = 'WarnContext';

            service.warn(message, context);

            expect(mockWinstonLogger.warn).toHaveBeenCalledWith(message, { context });
        });
    });

    describe('debug', () => {
        it('should call winston logger debug method with message', () => {
            const message = 'Test debug message';

            service.debug(message);

            expect(mockWinstonLogger.debug).toHaveBeenCalledWith(message, { context: undefined });
        });

        it('should call winston logger debug method with message and context', () => {
            const message = 'Test debug message';
            const context = 'DebugContext';

            service.debug(message, context);

            expect(mockWinstonLogger.debug).toHaveBeenCalledWith(message, { context });
        });
    });

    describe('Metadata support', () => {
        it('should log info with metadata', () => {
            const message = 'Test message';
            const context = 'TestContext';
            const metadata = { userId: '123', action: 'login' };

            service.info(message, context, metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                    userId: '123',
                    action: 'login',
                    environment: 'development',
                    serviceName: 'aegis-auth-service',
                    pid: expect.any(Number),
                }),
            );
        });

        it('should log error with metadata', () => {
            const message = 'Error occurred';
            const trace = 'Stack trace';
            const context = 'ErrorContext';
            const metadata = { requestId: 'req-123', statusCode: 500 };

            service.error(message, trace, context, metadata);

            expect(mockWinstonLogger.error).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                    trace,
                    requestId: 'req-123',
                    statusCode: 500,
                }),
            );
        });

        it('should log warn with metadata', () => {
            const message = 'Warning message';
            const context = 'WarnContext';
            const metadata = { correlationId: 'corr-456' };

            service.warn(message, context, metadata);

            expect(mockWinstonLogger.warn).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                    correlationId: 'corr-456',
                }),
            );
        });

        it('should log debug with metadata', () => {
            const message = 'Debug message';
            const context = 'DebugContext';
            const metadata = { query: 'SELECT * FROM users' };

            service.debug(message, context, metadata);

            expect(mockWinstonLogger.debug).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                    query: 'SELECT * FROM users',
                }),
            );
        });
    });

    describe('Sensitive data sanitization', () => {
        it('should redact password from metadata', () => {
            const message = 'User login attempt';
            const metadata = { username: 'john', password: 'secret123' };

            service.info(message, 'AuthContext', metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    username: 'john',
                    password: '***REDACTED***',
                }),
            );
        });

        it('should redact multiple sensitive fields', () => {
            const message = 'API call';
            const metadata = {
                apiKey: 'key123',
                token: 'bearer-token',
                accessToken: 'access123',
                refreshToken: 'refresh456',
                userId: '123',
            };

            service.info(message, 'APIContext', metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    apiKey: '***REDACTED***',
                    token: '***REDACTED***',
                    accessToken: '***REDACTED***',
                    refreshToken: '***REDACTED***',
                    userId: '123', // Should not be redacted
                }),
            );
        });

        it('should redact sensitive fields in nested objects', () => {
            const message = 'Request received';
            const metadata = {
                request: {
                    body: {
                        username: 'john',
                        password: 'secret',
                    },
                    headers: {
                        authorization: 'Bearer token123',
                    },
                },
            };

            service.info(message, 'HTTPContext', metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    request: {
                        body: {
                            username: 'john',
                            password: '***REDACTED***',
                        },
                        headers: {
                            authorization: '***REDACTED***',
                        },
                    },
                }),
            );
        });

        it('should handle arrays in metadata', () => {
            const message = 'Batch operation';
            const metadata = {
                users: [
                    { username: 'user1', password: 'pass1' },
                    { username: 'user2', token: 'token2' },
                ],
            };

            service.info(message, 'BatchContext', metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    users: [
                        { username: 'user1', password: '***REDACTED***' },
                        { username: 'user2', token: '***REDACTED***' },
                    ],
                }),
            );
        });
    });

    describe('Metadata enrichment', () => {
        it('should enrich metadata with environment info', () => {
            const message = 'Test message';
            const metadata = { customField: 'value' };

            service.info(message, 'TestContext', metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    customField: 'value',
                    environment: 'development',
                    serviceName: 'aegis-auth-service',
                    pid: expect.any(Number),
                }),
            );
        });
    });
});
