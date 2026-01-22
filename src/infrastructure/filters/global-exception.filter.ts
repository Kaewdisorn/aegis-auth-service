import {
    Catch,
    ArgumentsHost

} from '@nestjs/common';

@Catch()
export class GlobalExceptionFilter {

    constructor() {
        console.log('GlobalExceptionFilter initialized');
    }

    catch(exception: Error, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        console.error('Exception caught by GlobalExceptionFilter:', exception.message);
    }
}