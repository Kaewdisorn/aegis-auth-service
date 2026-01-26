import { AppConfig, IAppConfig } from '@application/ports/config.interface';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';



@Injectable()
export class AppConfigService implements IAppConfig {
    public readonly appConfig: AppConfig;

    constructor(private readonly configService: ConfigService) {
        this.appConfig = {
            nodeEnv: this.configService.get<string>('NODE_ENV') || 'development',
            host: this.configService.get<string>('HOST') || 'localhost',
            port: this.configService.get<number>('PORT') || 3000,
        };


    }

}