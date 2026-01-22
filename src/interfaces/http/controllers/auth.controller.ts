import { Controller, Post } from '@nestjs/common';

@Controller('auth')
export class AuthController {

    @Post('/')
    // throwError() {
    //     throw new Error('test error from AuthController');
    // }
    async register() {
        throw new Error('test error from AuthController');
        // return { message: 'User registered successfully' };
    }
}