import { Module } from '@nestjs/common';
import { AuthController } from './controllers/auth.controller';
import { RegisterUserUseCase } from '@application/use-cases/register-user.use-case';

@Module({
    controllers: [AuthController],
    providers: [RegisterUserUseCase],
})
export class AuthModule { }