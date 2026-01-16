import { Global, Module } from '@nestjs/common';
import { WinstonLoggerService } from './winston-logger.service';
import { ILogger } from '@application/ports/logger.interface';

@Global()
@Module({
    providers: [
        {
            provide: ILogger,
            useClass: WinstonLoggerService,
        },
    ],
    exports: [ILogger],
})
export class LoggerModule { }