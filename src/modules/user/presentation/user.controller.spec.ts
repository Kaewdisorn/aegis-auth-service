import { Test, TestingModule } from '@nestjs/testing';
import { UserController } from './user.controller';
import { RegisterUserUseCase } from '../application/use-cases/register-user.use-case';

describe('UserController', () => {
    let controller: UserController;
    const mockRegisterUserUseCase = { execute: jest.fn() };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [UserController],
            providers: [
                { provide: RegisterUserUseCase, useValue: mockRegisterUserUseCase },
            ],
        }).compile();

        controller = module.get<UserController>(UserController);
    });

    it('should call RegisterUserUseCase and return result', async () => {
        const dto = {
            serviceName: 'test-service',
            email: 'test@example.com',
            password: 'password123',
        };
        const expected = {
            gid: 'uuid-1',
            uid: 'uuid-2',
            email: dto.email,
            createdAt: new Date(),
        };

        mockRegisterUserUseCase.execute.mockResolvedValue(expected);

        const result = await controller.register(dto);
        expect(result).toEqual(expected);
        expect(mockRegisterUserUseCase.execute).toHaveBeenCalledWith(dto);
    });
});
