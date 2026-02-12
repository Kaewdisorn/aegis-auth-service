import { generateUUID } from "src/common/utils/uuid.util";

export class UserUid {

    static create(value: string): UserUid {
        const userId = generateUUID();
        console.log('Generated UserUid:', userId);
        return "";
    }
}