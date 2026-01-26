import { Global, Module } from '@nestjs/common';
import { AppConfigService } from './config';
import { IAppConfig } from '@application/ports/config.interface';

@Module({
    providers: [
        {
            provide: IAppConfig,
            useClass: AppConfigService,
        }
    ],
    exports: [IAppConfig],
})
export class AppConfigModule { }
