import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './domain/user.entity';
import { USER_REPOSITORY } from './domain/user-repository.interface';
import { TypeOrmUserRepository } from './infrastructure/typeorm-user.repository';
import { RegisterUserUseCase } from './application/use-cases/register-user.use-case';
import { UserController } from './presentation/user.controller';

@Module({
    imports: [TypeOrmModule.forFeature([User])],
    controllers: [UserController],
    providers: [
        RegisterUserUseCase,
        {
            provide: USER_REPOSITORY,
            useClass: TypeOrmUserRepository,
        },
    ],
    exports: [USER_REPOSITORY],
})
export class UserModule { }
