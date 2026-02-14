import { generateUUIDFromString } from "src/common/utils/uuid.util";

export class UserUid {
    private constructor(private readonly value: string) { }

    static create(value: string): UserUid {
        const userId = generateUUIDFromString(value);
        return new UserUid(userId);
    }


}