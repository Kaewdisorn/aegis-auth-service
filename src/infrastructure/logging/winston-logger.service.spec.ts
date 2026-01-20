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
});
