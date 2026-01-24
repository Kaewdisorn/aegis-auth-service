import { Global, Module } from '@nestjs/common';
import { ServerConfig } from './config';

@Module({
    providers: [ServerConfig],
    exports: [ServerConfig],
})
export class ServerConfigModule { }
