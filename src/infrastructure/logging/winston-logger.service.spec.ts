import { Test, TestingModule } from '@nestjs/testing';
import { WinstonLoggerService } from './winston-logger.service';
import { IAppConfig } from '@application/ports/config.interface';
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
            combine: jest.fn().mockReturnThis(),
            timestamp: jest.fn().mockReturnThis(),
            errors: jest.fn().mockReturnThis(),
            colorize: jest.fn().mockReturnThis(),
            printf: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
        },
        transports: {
            Console: jest.fn(),
            File: jest.fn(),
        },
    };
});

jest.mock('winston-daily-rotate-file', () => {
    return jest.fn();
});

describe('WinstonLoggerService', () => {
    let service: WinstonLoggerService;
    let mockWinstonLogger: any;

    beforeEach(async () => {
        jest.clearAllMocks();

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                WinstonLoggerService,
                {
                    provide: IAppConfig,
                    useValue: {
                        appConfig: {
                            nodeEnv: 'development',
                            host: 'localhost',
                            port: 3000,
                        },
                        logger: {
                            level: 'debug',
                            enableFileLogging: false,
                            logDir: './logs',
                        },
                    },
                },
            ],
        }).compile();

        service = module.get<WinstonLoggerService>(WinstonLoggerService);
        mockWinstonLogger = (winston.createLogger as jest.Mock).mock.results[0].value;
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('constructor', () => {
        it('should create winston logger with configured log level', () => {
            expect(winston.createLogger).toHaveBeenCalled();
        });

        it('should use "info" as default log level when LOG_LEVEL is not set', async () => {
            jest.clearAllMocks();

            const module: TestingModule = await Test.createTestingModule({
                providers: [
                    WinstonLoggerService,
                    {
                        provide: IAppConfig,
                        useValue: {
                            appConfig: {
                                nodeEnv: 'development',
                                host: 'localhost',
                                port: 3000,
                            },
                            logger: {
                                level: 'info',
                                enableFileLogging: false,
                                logDir: './logs',
                            },
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

        it('should configure Console transport for development', () => {
            expect(winston.transports.Console).toHaveBeenCalled();
        });

        it('should use production transports when NODE_ENV is production', async () => {
            jest.clearAllMocks();
            const DailyRotateFile = require('winston-daily-rotate-file');

            const module: TestingModule = await Test.createTestingModule({
                providers: [
                    WinstonLoggerService,
                    {
                        provide: IAppConfig,
                        useValue: {
                            appConfig: {
                                nodeEnv: 'production',
                                host: 'localhost',
                                port: 3000,
                            },
                            logger: {
                                level: 'info',
                                enableFileLogging: true,
                                logDir: './logs',
                            },
                        },
                    },
                ],
            }).compile();

            const prodService = module.get<WinstonLoggerService>(WinstonLoggerService);

            expect(prodService).toBeDefined();
            expect(winston.transports.Console).toHaveBeenCalled();
            expect(DailyRotateFile).toHaveBeenCalledTimes(2); // One for app logs, one for error logs
        });
    });

    describe('info', () => {
        it('should call winston logger info method with message', () => {
            const message = 'Test info message';

            service.info(message);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context: undefined,
                })
            );
        });

        it('should call winston logger info method with message and context', () => {
            const message = 'Test info message';
            const context = 'TestContext';

            service.info(message, context);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                })
            );
        });

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
    });

    describe('error', () => {
        it('should call winston logger error method with message', () => {
            const message = 'Test error message';

            service.error(message);

            expect(mockWinstonLogger.error).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context: undefined,
                    trace: undefined,
                })
            );
        });

        it('should call winston logger error method with message and trace', () => {
            const message = 'Test error message';
            const trace = 'Error stack trace';

            service.error(message, trace);

            expect(mockWinstonLogger.error).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context: undefined,
                    trace,
                })
            );
        });

        it('should call winston logger error method with message, trace and context', () => {
            const message = 'Test error message';
            const trace = 'Error stack trace';
            const context = 'ErrorContext';

            service.error(message, trace, context);

            expect(mockWinstonLogger.error).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                    trace,
                })
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
                    environment: 'development',
                    serviceName: 'aegis-auth-service',
                }),
            );
        });
    });

    describe('warn', () => {
        it('should call winston logger warn method with message', () => {
            const message = 'Test warning message';

            service.warn(message);

            expect(mockWinstonLogger.warn).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context: undefined,
                })
            );
        });

        it('should call winston logger warn method with message and context', () => {
            const message = 'Test warning message';
            const context = 'WarnContext';

            service.warn(message, context);

            expect(mockWinstonLogger.warn).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                })
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
                    environment: 'development',
                    serviceName: 'aegis-auth-service',
                }),
            );
        });
    });

    describe('debug', () => {
        it('should call winston logger debug method with message', () => {
            const message = 'Test debug message';

            service.debug(message);

            expect(mockWinstonLogger.debug).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context: undefined,
                })
            );
        });

        it('should call winston logger debug method with message and context', () => {
            const message = 'Test debug message';
            const context = 'DebugContext';

            service.debug(message, context);

            expect(mockWinstonLogger.debug).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    context,
                })
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

        it('should redact cookie from metadata', () => {
            const message = 'Request with cookie';
            const metadata = { cookie: 'session=abc123', userId: '456' };

            service.info(message, 'HTTPContext', metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    cookie: '***REDACTED***',
                    userId: '456',
                }),
            );
        });

        it('should redact secret from metadata', () => {
            const message = 'Config loaded';
            const metadata = { secret: 'my-secret-key', appName: 'aegis' };

            service.info(message, 'ConfigContext', metadata);

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    secret: '***REDACTED***',
                    appName: 'aegis',
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

        it('should include serviceName in enriched metadata', () => {
            const message = 'Service started';

            service.info(message, 'Bootstrap', { port: 3000 });

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    serviceName: 'aegis-auth-service',
                }),
            );
        });

        it('should include process PID in enriched metadata', () => {
            const message = 'Process info';

            service.info(message, 'System', {});

            expect(mockWinstonLogger.info).toHaveBeenCalledWith(
                message,
                expect.objectContaining({
                    pid: process.pid,
                }),
            );
        });
    });
});
