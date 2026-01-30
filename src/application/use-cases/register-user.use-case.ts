import { RegisterUserDto } from "@application/dtos/register-user.dto";
import { Injectable } from "@nestjs/common";

@Injectable()
export class RegisterUserUseCase {

    async execute(dto: RegisterUserDto) {
        console.log('Registering user with email:', dto.email);
    }
}