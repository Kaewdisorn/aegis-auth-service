import { Global, Module } from '@nestjs/common';
import { WinstonLoggerService } from './winston-logger.service';
import { ILogger } from '@application/ports/logger.interface';
import { AppConfigModule } from '@infrastructure/config/server-config.module';

@Module({
    imports: [AppConfigModule],
    providers: [
        {
            provide: ILogger,
            useClass: WinstonLoggerService,
        },
    ],
    exports: [ILogger],
})
export class LoggerModule { }