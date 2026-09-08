export function secureRandomBytes(n: number): Uint8Array;
export function secureRandomToken(n?: number): string;
export function secureRandomHex(n?: number): string;

export function constantTimeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean;

export function isValidEmail(email: string): boolean;
export function isValidUrl(url: string): boolean;
export function isAllowListed(value: string, allowedChars: string): boolean;
export function sanitizeFilename(filename: string): string;
export function escapeHtml(value: string): string;
