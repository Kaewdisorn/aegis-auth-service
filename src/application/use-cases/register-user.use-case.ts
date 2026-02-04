import { RegisterUserDto } from "@application/dtos/register-user.dto";
import { Email } from "@domain/value-objects/email.vo";
import { Injectable } from "@nestjs/common";

@Injectable()
export class RegisterUserUseCase {

    async execute(dto: RegisterUserDto) {
        // Create value objects (validates format)
        const email = Email.create(dto.email);
        console.log('Created Email VO:', email.toString());
    }
}