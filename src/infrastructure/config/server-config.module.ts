import { Global, Module } from '@nestjs/common';
import { AppConfigService } from './config';

@Module({
    providers: [AppConfigService],
    exports: [AppConfigService],
})
export class AppConfigModule { }
