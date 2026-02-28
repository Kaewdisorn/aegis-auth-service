import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
} from 'typeorm';

export const USER_SERVICE_GID = '00000000-0000-0000-0000-000000000001';

@Entity('users')
export class User {
    @Column({ type: 'uuid' })
    gid: string = USER_SERVICE_GID;

    @PrimaryGeneratedColumn('uuid')
    uid: string;

    @Column({ unique: true })
    email: string;

    @Column()
    password: string;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt: Date;
}
