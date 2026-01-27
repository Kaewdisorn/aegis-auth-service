export interface AppConfig {
    nodeEnv: string;
    host: string;
    port: number;
}

export interface LoggerConfig {
    level: string;
    enableFileLogging: boolean;
    logDir: string;
}


export interface IAppConfig {
    readonly appConfig: AppConfig;
    readonly logger: LoggerConfig;
}

export const IAppConfig = Symbol('IAppConfig');