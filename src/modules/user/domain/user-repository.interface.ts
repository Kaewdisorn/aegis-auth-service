import { User } from './user.entity';

export const USER_REPOSITORY = Symbol('USER_REPOSITORY');

export interface IUserRepository {
    findByEmail(email: string): Promise<User | null>;
    save(user: Partial<User>): Promise<User>;
}
