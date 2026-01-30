import { IsEmail, IsNotEmpty } from 'class-validator';
export class RegisterUserDto {
    @IsEmail({}, { message: 'Invalid email format' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;
    password: string;
}