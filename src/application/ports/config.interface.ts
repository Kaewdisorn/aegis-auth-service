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

export interface DatabaseConfig {
    readonly host: string;
    readonly port: number;
    readonly database: string;
    readonly username: string;
    readonly password: string;
}


export interface IAppConfig {
    readonly appConfig: AppConfig;
    readonly logger: LoggerConfig;
    // readonly database: DatabaseConfig;
}

export const IAppConfig = Symbol('IAppConfig');