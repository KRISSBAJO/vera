export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message?: string,
    public readonly details?: unknown,
  ) {
    super(message ?? code);
    this.name = 'HttpError';
  }
}

export const unauthorized = (code = 'UNAUTHORIZED') => new HttpError(401, code);
export const forbidden = (code: string, message?: string) => new HttpError(403, code, message);
export const notFound = (what: string) => new HttpError(404, 'NOT_FOUND', `${what} not found`);
export const conflict = (code: string, message?: string) => new HttpError(409, code, message);
export const tooManyRequests = (message: string) => new HttpError(429, 'RATE_LIMITED', message);
