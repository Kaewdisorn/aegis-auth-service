import { Module } from '@nestjs/common';
import { UserController } from './presentation/user.controller';
import { RegisterUserUseCase } from './application/use-cases/register-user.use-case';

@Module({
    controllers: [UserController],
    providers: [RegisterUserUseCase],
})
export class UserModule { }
