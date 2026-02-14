import { Email } from "@domain/value-objects/email.vo";
import { UserUuid } from "@domain/value-objects/user-uuid.vo";

export class User {
    public readonly userGid: UserUuid;
    public readonly userUid: UserUuid;
    public readonly email: Email;
    public readonly passwordHash: string;
    public readonly createdAt: Date;
    public readonly updatedAt: Date;

}