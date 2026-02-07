import { RegisterUserDto } from "@application/dtos/register-user.dto";
import { Email } from "@domain/value-objects/email.vo";
import { Password } from "@domain/value-objects/password.vo";
import { Injectable } from "@nestjs/common";

@Injectable()
export class RegisterUserUseCase {

    async execute(dto: RegisterUserDto) {
        // Create value objects (validates format)
        const email = Email.create(dto.email);
        Password.create(dto.password); // validates password format
        console.log('Created Email VO:', email.toString());
        console.log('Created Password VO:', Password.create(dto.password).toString());

        // Check if user already exists
    }
}