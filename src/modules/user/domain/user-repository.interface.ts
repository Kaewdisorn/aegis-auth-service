import { User } from './user.entity';

export const USER_REPOSITORY = Symbol('USER_REPOSITORY');

export interface IUserRepository {
    save(user: User): Promise<User>;
    findByEmail(email: string): Promise<User | null>;
    findByUid(uid: string): Promise<User | null>;
}
