import { CorrelationIdMiddleware } from './correlation-id.middleware';
import { Request, Response } from 'express';

describe('CorrelationIdMiddleware', () => {
  let middleware: CorrelationIdMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: jest.Mock;

  beforeEach(() => {
    middleware = new CorrelationIdMiddleware();
    mockRequest = { headers: {} };
    mockResponse = { setHeader: jest.fn() };
    nextFunction = jest.fn();
  });

  it('should generate correlation ID if not provided', () => {
    middleware.use(
      mockRequest as Request,
      mockResponse as Response,
      nextFunction,
    );

    expect(mockRequest['correlationId']).toBeDefined();
    expect(mockRequest['correlationId']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(mockResponse.setHeader).toHaveBeenCalledWith(
      'X-Correlation-ID',
      mockRequest['correlationId'],
    );
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should use existing correlation ID from header', () => {
    const existingId = 'existing-correlation-id-123';
    mockRequest.headers = { 'x-correlation-id': existingId };

    middleware.use(
      mockRequest as Request,
      mockResponse as Response,
      nextFunction,
    );

    expect(mockRequest['correlationId']).toBe(existingId);
    expect(mockResponse.setHeader).toHaveBeenCalledWith(
      'X-Correlation-ID',
      existingId,
    );
    expect(nextFunction).toHaveBeenCalled();
  });

  it('should set correlation ID on response header', () => {
    middleware.use(
      mockRequest as Request,
      mockResponse as Response,
      nextFunction,
    );

    expect(mockResponse.setHeader).toHaveBeenCalledWith(
      'X-Correlation-ID',
      expect.any(String),
    );
  });

  it('should always call next()', () => {
    middleware.use(
      mockRequest as Request,
      mockResponse as Response,
      nextFunction,
    );

    expect(nextFunction).toHaveBeenCalledTimes(1);
  });
});
