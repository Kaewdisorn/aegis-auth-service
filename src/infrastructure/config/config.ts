import { IAppConfig } from '@application/ports/config.interface';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';



@Injectable()
export class ServerConfig {
    public readonly serverConfig: IAppConfig;

    constructor(private readonly configService: ConfigService) {
        this.serverConfig = {
            nodeEnv: this.configService.get<string>('NODE_ENV') || 'development',
            host: this.configService.get<string>('HOST') || 'localhost',
            port: this.configService.get<number>('PORT') || 3000,
        };
    }
}