import { Inject, Injectable } from "@nestjs/common";
import { RegisterUserDto } from "../dto/register-user.dto";
import { UserResponseDto } from "../dto/user-response.dto";
import { USER_REPOSITORY } from "../../domain/user-repository.interface";
import type { IUserRepository } from "../../domain/user-repository.interface";

@Injectable()
export class RegisterUserUseCase {
    constructor(
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
    ) { }

    async execute(dto: RegisterUserDto): Promise<UserResponseDto> {
        const existingUser = await this.userRepository.findByEmail(dto.email);

        return new UserResponseDto();
    }
}