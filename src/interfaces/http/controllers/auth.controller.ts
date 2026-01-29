import { RegisterUserDto } from '@application/dtos/register-user.dto';
import { Body, Controller, Post } from '@nestjs/common';

@Controller('auth')
export class AuthController {

    @Post('/')
    async register(@Body() dto: RegisterUserDto): Promise<any> {
        console.log(dto);
        //throw new Error('testtt error from AuthController');
        // throw new BadRequestException('Invalid input');
        // return { message: 'User registered successfully' };
    }
}