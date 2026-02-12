import { IsNotEmpty, IsString } from 'class-validator';
export class RegisterUserDto {
    @IsString({ message: 'Email must be a string' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;

    @IsString({ message: 'Password must be a string' })
    @IsNotEmpty({ message: 'Password is required' })
    password: string;

    @IsString({ message: 'Service name must be a string' })
    @IsNotEmpty({ message: 'Service name is required' })
    serviceName: string;
}