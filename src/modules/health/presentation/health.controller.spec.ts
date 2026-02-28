import { Test, TestingModule } from '@nestjs/testing';
import { HealthController } from './health.controller';
import { HealthCheckService, TypeOrmHealthIndicator } from '@nestjs/terminus';

describe('HealthController', () => {
    let controller: HealthController;
    const mockHealthCheckService = {
        check: jest.fn(),
    };
    const mockTypeOrmHealthIndicator = {
        pingCheck: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [HealthController],
            providers: [
                { provide: HealthCheckService, useValue: mockHealthCheckService },
                { provide: TypeOrmHealthIndicator, useValue: mockTypeOrmHealthIndicator },
            ],
        }).compile();

        controller = module.get<HealthController>(HealthController);
        jest.clearAllMocks();
    });

    it('should return healthy status when database is up', async () => {
        const expected = {
            status: 'ok',
            info: { database: { status: 'up' } },
        };

        mockHealthCheckService.check.mockResolvedValue(expected);

        const result = await controller.check();

        expect(result).toEqual(expected);
        expect(mockHealthCheckService.check).toHaveBeenCalledWith([
            expect.any(Function),
        ]);
    });

    it('should call db.pingCheck when health check executes', async () => {
        mockHealthCheckService.check.mockImplementation(
            (indicators: (() => Promise<unknown>)[]) => {
                indicators.forEach((fn) => fn());
                return Promise.resolve({ status: 'ok' });
            },
        );

        await controller.check();

        expect(mockTypeOrmHealthIndicator.pingCheck).toHaveBeenCalledWith('database');
    });
});
