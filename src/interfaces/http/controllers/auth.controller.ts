import { BadRequestException, Controller, Post } from '@nestjs/common';

@Controller('auth')
export class AuthController {

    @Post('/')
    // throwError() {
    //     throw new Error('test error from AuthController');
    // }
    async register() {
        //throw new Error('testtt error from AuthController');
        throw new BadRequestException('Invalid input');
        // return { message: 'User registered successfully' };
    }
}