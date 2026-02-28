import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { RegisterUserDto } from '../application/dto/register-user.dto';
import { RegisterUserUseCase } from '../application/use-cases/register-user.use-case';
import { UserResponseDto } from '../application/dto/user-response.dto';


@Controller('users')
export class UserController {
    constructor(private readonly registerUserUseCase: RegisterUserUseCase) { }

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() dto: RegisterUserDto): Promise<UserResponseDto> {
        return this.registerUserUseCase.execute(dto);
    }
}