export function secureRandomBytes(n: number): Buffer;
export function secureRandomToken(n?: number): string;
export function secureRandomHex(n?: number): string;

export interface PasswordHasherOptions {
  memoryCostKiB?: number;
  timeCost?: number;
  parallelism?: number;
  hashLength?: number;
}
export class PasswordHasher {
  constructor(options?: PasswordHasherOptions);
  hash(password: string): Promise<string>;
  verify(password: string, encodedHash: string): Promise<boolean>;
  needsRehash(encodedHash: string): Promise<boolean>;
}

export class DecryptionError extends Error {}
export class SymmetricEncryptor {
  generateKey(): Buffer;
  encrypt(key: Buffer, plaintext: Buffer, aad?: Buffer): Buffer;
  decrypt(key: Buffer, blob: Buffer, aad?: Buffer): Buffer;
  encryptToString(key: Buffer, plaintext: Buffer, aad?: Buffer): string;
  decryptFromString(key: Buffer, encoded: string, aad?: Buffer): Buffer;
}

export function isValidEmail(email: string): boolean;
export function isValidUrl(url: string): boolean;
export function isAllowListed(value: string, allowedChars: string): boolean;
export function sanitizeFilename(filename: string): string;
export function escapeHtml(value: string): string;

export class CsrfTokenManager {
  constructor(secret: Buffer, ttlMs?: number);
  generate(sessionId: string): string;
  verify(sessionId: string, token: string): boolean;
}

export interface RateLimiterStore {
  increment(key: string, windowMs: number): number | Promise<number>;
}
export class MemoryRateLimiterStore implements RateLimiterStore {
  increment(key: string, windowMs: number): number;
}
export class RedisRateLimiterStore implements RateLimiterStore {
  constructor(client: unknown, keyPrefix?: string);
  increment(key: string, windowMs: number): Promise<number>;
}
export class RateLimiter {
  constructor(store: RateLimiterStore, limit: number, windowMs: number);
  allow(key: string): Promise<boolean>;
}

export function constantTimeEqual(a: string | Buffer, b: string | Buffer): boolean;

export function isPrivateOrReservedIp(ip: string): boolean;
export function isPublicHttpUrl(url: string): Promise<boolean>;

export class VersionedEncryptor {
  constructor(keys: Map<number, Buffer> | Record<number, Buffer>, currentKeyId: number);
  addKey(id: number, key: Buffer): void;
  setCurrentKeyId(id: number): void;
  encrypt(plaintext: Buffer, aad?: Buffer): Buffer;
  decrypt(blob: Buffer, aad?: Buffer): Buffer;
}
