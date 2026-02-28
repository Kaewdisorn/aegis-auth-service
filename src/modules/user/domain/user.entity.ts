import {
    Entity,
    PrimaryColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
    BeforeInsert,
} from 'typeorm';
import { v5 as uuidv5 } from 'uuid';

export const USER_SERVICE_GID = '00000000-0000-0000-0000-000000000001';

@Entity('users')
export class User {
    @Column({ type: 'uuid' })
    gid: string = USER_SERVICE_GID;

    @PrimaryColumn({ type: 'uuid' })
    uid: string;

    @Column({ unique: true })
    email: string;

    @Column()
    password: string;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt: Date;

    @BeforeInsert()
    generateUid() {
        this.uid = uuidv5(this.email, USER_SERVICE_GID);
    }
}
