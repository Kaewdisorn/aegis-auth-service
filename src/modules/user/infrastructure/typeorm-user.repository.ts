import { Repository } from "typeorm";
import { IUserRepository } from "../domain/user-repository.interface";
import { User } from "../domain/user.entity";
import { InjectRepository } from "@nestjs/typeorm";

export class TypeOrmUserRepository implements IUserRepository {
    constructor(
        @InjectRepository(User)
        private readonly userRepo: Repository<User>,
    ) { }

    async findByEmail(email: string): Promise<User | null> {
        return this.userRepo.findOne({ where: { email } });
    }

    async save(user: Partial<User>): Promise<User> {

        const newUser = this.userRepo.create(user);
        return this.userRepo.save(newUser);
    }
}