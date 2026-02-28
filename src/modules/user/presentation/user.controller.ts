import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { RegisterUserDto } from '../application/dto/register-user.dto';
import { RegisterUserUseCase } from '../application/use-cases/register-user.use-case';


@Controller('users')
export class UserController {
    constructor(private readonly registerUserUseCase: RegisterUserUseCase) { }

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    register(@Body() dto: RegisterUserDto) {
        return this.registerUserUseCase.execute(dto);
    }
}