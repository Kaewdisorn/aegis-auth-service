import { User } from "../../domain/user.entity";

export class UserResponseDto {
    gid!: string;
    uid!: string;
    email!: string;
    createdAt!: Date;

    static fromEntity(user: User): UserResponseDto {
        const dto = new UserResponseDto();
        dto.gid = user.gid;
        dto.uid = user.uid;
        dto.email = user.email;
        dto.createdAt = user.createdAt;
        return dto;
    }
}