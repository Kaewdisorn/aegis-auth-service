export interface AppConfig {
    nodeEnv: string;
    host: string;
    port: number;
}

export interface IAppConfig {
    readonly appConfig: AppConfig;
}

export const IAppConfig = Symbol('IAppConfig');