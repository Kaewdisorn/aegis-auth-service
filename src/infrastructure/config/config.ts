import { AppConfig, IAppConfig, LoggerConfig } from '@application/ports/config.interface';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';



@Injectable()
export class AppConfigService implements IAppConfig {
    public readonly appConfig: AppConfig;
    public readonly logger: LoggerConfig;

    constructor(private readonly configService: ConfigService) {
        this.appConfig = {
            nodeEnv: this.configService.get<string>('NODE_ENV') || 'development',
            host: this.configService.get<string>('HOST') || 'localhost',
            port: this.configService.get<number>('PORT') || 3000,
        };

        this.logger = {
            level: this.configService.get<string>('LOG_LEVEL') || 'info',
            enableFileLogging: this.configService.get<string>('ENABLE_FILE_LOGGING') === 'true',
            logDir: this.configService.get<string>('LOG_DIR') || './logs',
        };


    }


}