import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppConfigService } from './config';
import { IAppConfig } from '@application/ports/config.interface';

@Module({
    imports: [ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' })],
    providers: [
        {
            provide: IAppConfig,
            useClass: AppConfigService,
        },
    ],
    exports: [IAppConfig],
})
export class AppConfigModule { }
