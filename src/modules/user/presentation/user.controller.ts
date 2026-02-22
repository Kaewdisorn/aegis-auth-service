import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { RegisterUserDto } from '../application/dto/register-user.dto';


@Controller('users')
export class UserController {

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    register(@Body() dto: RegisterUserDto) {
        // Implement user registration logic here
    }
}