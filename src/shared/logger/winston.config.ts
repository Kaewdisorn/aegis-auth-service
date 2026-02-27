import { utilities } from 'nest-winston';
import * as winston from 'winston';

const isProduction = process.env.NODE_ENV === 'production';

export const winstonConfig = {
    transports: [
        // Development: pretty-printed console output
        ...(!isProduction
            ? [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.timestamp(),
                        utilities.format.nestLike('AegisAuth', {
                            prettyPrint: true,
                            colors: true,
                        }),
                    ),
                }),
            ]
            : []),

        // Production: structured JSON for log aggregators
        ...(isProduction
            ? [
                new winston.transports.Console({
                    format: winston.format.combine(
                        winston.format.timestamp(),
                        winston.format.json(),
                    ),
                }),
            ]
            : []),
    ],
};
