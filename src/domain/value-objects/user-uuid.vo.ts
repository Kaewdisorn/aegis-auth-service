import { generateUUIDFromString } from "src/common/utils/uuid.util";

export class UserUuid {
    private constructor(private readonly value: string) { }

    static create(value: string): UserUuid {
        const userId = generateUUIDFromString(value);
        return new UserUuid(userId);
    }


}