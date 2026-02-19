import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common';


@Controller('users')
export class UserController {

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    register(@Body() createUserDto: any) {
        // Implement user registration logic here
    }
}