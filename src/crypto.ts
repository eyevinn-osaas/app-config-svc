import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';

export function validateEncryptionKey(keyBase64: string): void {
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(
      `PARAMETER_ENCRYPTION_KEY must be a base64 string decoding to 16, 24, or 32 bytes; got ${key.length} bytes`
    );
  }
}

export interface EncryptResult {
  encrypted: string;
  iv: string;
  tag: string;
}

export function encrypt(plaintext: string, keyBase64: string): EncryptResult {
  const key = Buffer.from(keyBase64, 'base64');
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64')
  };
}

export function decrypt(
  encrypted: string,
  iv: string,
  tag: string,
  keyBase64: string
): string {
  const key = Buffer.from(keyBase64, 'base64');
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'base64')),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}
