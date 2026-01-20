import { Controller, Post } from '@nestjs/common';

@Controller('auth')
export class AuthController {

    @Post('/')
    async register() {
        return { message: 'User registered successfully' };
    }
}