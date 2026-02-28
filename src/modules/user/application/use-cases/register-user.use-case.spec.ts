import { Test, TestingModule } from '@nestjs/testing';
import { RegisterUserUseCase } from './register-user.use-case';
import { USER_REPOSITORY } from '../../domain/user-repository.interface';
import { UserAlreadyExistsException } from '../../domain/exceptions/user-already-exists.exception';

describe('RegisterUserUseCase', () => {
    let useCase: RegisterUserUseCase;
    const mockUserRepository = {
        findByEmail: jest.fn(),
        save: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                RegisterUserUseCase,
                { provide: USER_REPOSITORY, useValue: mockUserRepository },
            ],
        }).compile();

        useCase = module.get<RegisterUserUseCase>(RegisterUserUseCase);
        jest.clearAllMocks();
    });

    it('should register a new user successfully', async () => {
        const dto = {
            email: 'test@example.com',
            password: 'password123',
        };

        mockUserRepository.findByEmail.mockResolvedValue(null);
        mockUserRepository.save.mockResolvedValue({
            gid: 'uuid-1',
            uid: 'uuid-2',
            ...dto,
            password: 'hashed',
            createdAt: new Date(),
            updatedAt: new Date(),
        });

        const result = await useCase.execute(dto);

        expect(result.email).toBe(dto.email);
        expect(result).not.toHaveProperty('password');
        expect(mockUserRepository.findByEmail).toHaveBeenCalledWith(dto.email);
        expect(mockUserRepository.save).toHaveBeenCalled();
    });

    it('should throw UserAlreadyExistsException if email is taken', async () => {
        const dto = {
            email: 'taken@example.com',
            password: 'password123',
        };

        mockUserRepository.findByEmail.mockResolvedValue({ gid: 'existing-gid' });

        await expect(useCase.execute(dto)).rejects.toThrow(
            UserAlreadyExistsException,
        );
        expect(mockUserRepository.save).not.toHaveBeenCalled();
    });
});
