import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface AppConfig {
    nodeEnv: string;
    host: string;
    port: number;
}

@Injectable()
export class ServerConfig {
    public readonly serverConfig: AppConfig;

    constructor(private readonly configService: ConfigService) {
        this.serverConfig = {
            nodeEnv: this.configService.get<string>('NODE_ENV') || 'development',
            host: this.configService.get<string>('HOST') || 'localhost',
            port: this.configService.get<number>('PORT') || 3000,
        };
    }
}