import { Injectable } from "@nestjs/common";
import { RegisterUserDto } from "../dto/register-user.dto";
import { UserResponseDto } from "../dto/user-response.dto";

@Injectable()
export class RegisterUserUseCase {

    async execute(dto: RegisterUserDto): Promise<UserResponseDto> {

        return new UserResponseDto();
    }
}