import { Global, Module } from '@nestjs/common';
import { NestLoggerService } from './winston-logger.service';
import { ILogger } from '@application/ports/logger.interface';

@Global()
@Module({
    providers: [
        {
            provide: ILogger,
            useClass: NestLoggerService,
        },
    ],
    exports: [ILogger],
})
export class LoggerModule { }