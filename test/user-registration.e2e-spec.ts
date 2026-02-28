import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../src/app.module';

describe('User Registration (e2e)', () => {
    let app: INestApplication;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();
        app.useGlobalPipes(
            new ValidationPipe({
                whitelist: true,
                forbidNonWhitelisted: true,
                transform: true,
            }),
        );
        await app.init();
    });

    afterAll(async () => {
        await app.close();
    });

    it('POST /users/register — should create a user (201)', () => {
        return request(app.getHttpServer())
            .post('/users/register')
            .send({
                email: `e2e-${Date.now()}@example.com`,
                password: 'securePass1',
            })
            .expect(201)
            .expect((res) => {
                expect(res.body.gid).toBeDefined();
                expect(res.body.uid).toBeDefined();
                expect(res.body.email).toBeDefined();
                expect(res.body.createdAt).toBeDefined();
                expect(res.body).not.toHaveProperty('password');
            });
    });

    it('POST /users/register — duplicate email (409)', async () => {
        const email = `e2e-dup-${Date.now()}@example.com`;
        const dto = { email, password: 'securePass1' };

        await request(app.getHttpServer())
            .post('/users/register')
            .send(dto)
            .expect(201);

        return request(app.getHttpServer())
            .post('/users/register')
            .send(dto)
            .expect(409);
    });

    it('POST /users/register — invalid email (400)', () => {
        return request(app.getHttpServer())
            .post('/users/register')
            .send({
                email: 'not-an-email',
                password: 'securePass1',
            })
            .expect(400);
    });

    it('POST /users/register — short password (400)', () => {
        return request(app.getHttpServer())
            .post('/users/register')
            .send({
                email: `e2e-short-${Date.now()}@example.com`,
                password: 'short',
            })
            .expect(400);
    });

    it('POST /users/register — unknown fields rejected (400)', () => {
        return request(app.getHttpServer())
            .post('/users/register')
            .send({
                email: `e2e-extra-${Date.now()}@example.com`,
                password: 'securePass1',
                role: 'admin',
            })
            .expect(400);
    });
});
