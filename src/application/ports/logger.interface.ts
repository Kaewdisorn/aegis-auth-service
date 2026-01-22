export interface LogMetadata {
    [key: string]: any;
}

export interface SecurityContext {
    userId?: string;
    username?: string;
    ipAddress?: string;
    userAgent?: string;
    action?: string;
}

export interface PerformanceMetrics {
    duration?: number;
    memoryUsage?: number;
    statusCode?: number;
}

export interface RequestContext {
    correlationId?: string;
    requestId?: string;
    path?: string;
    method?: string;
}

export interface ExtendedLogMetadata extends LogMetadata {
    correlationId?: string;
    requestId?: string;
    userId?: string;
    securityContext?: SecurityContext;
    performance?: PerformanceMetrics;
    request?: RequestContext;
}



export interface ILogger {
    info(message: string, context: string, metadata?: LogMetadata): void;
    error(message: string, context: string, trace?: string, metadata?: LogMetadata): void;
    warn(message: string, context: string, metadata?: LogMetadata): void;
    debug(message: string, context: string, metadata?: LogMetadata): void;
}

export const ILogger = Symbol('ILogger');