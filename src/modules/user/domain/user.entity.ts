import {
    Entity,
    PrimaryColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
    BeforeInsert,
} from 'typeorm';
import { v5 as uuidv5 } from 'uuid';

export const NAMESPACE = 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d';

@Entity('users')
export class User {
    @Column({ type: 'uuid' })
    gid!: string;

    @PrimaryColumn({ type: 'uuid' })
    uid!: string;

    @Column()
    serviceName!: string;

    @Column({ unique: true })
    email!: string;

    @Column()
    password!: string;

    @CreateDateColumn({ name: 'created_at' })
    createdAt!: Date;

    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt!: Date;

    @BeforeInsert()
    generateIds() {
        this.gid = uuidv5(this.serviceName, NAMESPACE);
        this.uid = uuidv5(this.email, NAMESPACE);
    }
}
