import { Inject, Injectable } from "@nestjs/common";
import * as bcrypt from "bcrypt";
import { RegisterUserDto } from "../dto/register-user.dto";
import { UserResponseDto } from "../dto/user-response.dto";
import { USER_REPOSITORY } from "../../domain/user-repository.interface";
import type { IUserRepository } from "../../domain/user-repository.interface";
import { UserAlreadyExistsException } from "../../domain/exceptions/user-already-exists.exception";

@Injectable()
export class RegisterUserUseCase {
    constructor(
        @Inject(USER_REPOSITORY)
        private readonly userRepository: IUserRepository,
    ) { }

    async execute(dto: RegisterUserDto): Promise<UserResponseDto> {
        const existingUser = await this.userRepository.findByEmail(dto.email);

        if (existingUser) {
            throw new UserAlreadyExistsException(dto.email);
        }

        const hashedPassword = await bcrypt.hash(dto.password, 10);

        const user = await this.userRepository.save({
            email: dto.email,
            password: hashedPassword,
        });

        return UserResponseDto.fromEntity(user);
    }
}