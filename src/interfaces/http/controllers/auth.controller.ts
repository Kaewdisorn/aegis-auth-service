import { RegisterUserDto } from '@application/dtos/register-user.dto';
import { RegisterUserUseCase } from '@application/use-cases/register-user.use-case';
import { Body, Controller, Post } from '@nestjs/common';

@Controller('auth')
export class AuthController {
    constructor(private readonly registerUserUseCase: RegisterUserUseCase) { }

    @Post('/')
    async register(@Body() dto: RegisterUserDto): Promise<any> {
        const user = await this.registerUserUseCase.execute(dto);
        //throw new Error('testtt error from AuthController');
        // throw new BadRequestException('Invalid input');
        // return { message: 'User registered successfully' };
    }
}