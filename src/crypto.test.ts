import { encrypt, decrypt, validateEncryptionKey } from './crypto';
import { randomBytes } from 'crypto';

// Generate a deterministic 256-bit key for tests (base64)
const TEST_KEY = randomBytes(32).toString('base64');

describe('crypto helpers', () => {
  describe('encrypt / decrypt round-trip', () => {
    it('decrypts back to the original plaintext', () => {
      const plaintext = 'my-secret-password-123!';
      const { encrypted, iv, tag } = encrypt(plaintext, TEST_KEY);
      const result = decrypt(encrypted, iv, tag, TEST_KEY);
      expect(result).toBe(plaintext);
    });

    it('handles empty string', () => {
      const { encrypted, iv, tag } = encrypt('', TEST_KEY);
      expect(decrypt(encrypted, iv, tag, TEST_KEY)).toBe('');
    });

    it('handles unicode / special characters', () => {
      const plaintext = 'pässwörd 🔑 <>&"\'';
      const { encrypted, iv, tag } = encrypt(plaintext, TEST_KEY);
      expect(decrypt(encrypted, iv, tag, TEST_KEY)).toBe(plaintext);
    });

    it('produces different ciphertext for the same plaintext each call (random IV)', () => {
      const plaintext = 'same-value';
      const result1 = encrypt(plaintext, TEST_KEY);
      const result2 = encrypt(plaintext, TEST_KEY);
      // IVs must differ
      expect(result1.iv).not.toBe(result2.iv);
      // Ciphertexts must differ
      expect(result1.encrypted).not.toBe(result2.encrypted);
      // Both must decrypt correctly
      expect(
        decrypt(result1.encrypted, result1.iv, result1.tag, TEST_KEY)
      ).toBe(plaintext);
      expect(
        decrypt(result2.encrypted, result2.iv, result2.tag, TEST_KEY)
      ).toBe(plaintext);
    });

    it('throws when decrypting with a wrong key', () => {
      const { encrypted, iv, tag } = encrypt('secret', TEST_KEY);
      const wrongKey = randomBytes(32).toString('base64');
      expect(() => decrypt(encrypted, iv, tag, wrongKey)).toThrow();
    });

    it('throws when the auth tag is tampered', () => {
      const { encrypted, iv } = encrypt('secret', TEST_KEY);
      const badTag = randomBytes(16).toString('base64');
      expect(() => decrypt(encrypted, iv, badTag, TEST_KEY)).toThrow();
    });
  });

  describe('validateEncryptionKey', () => {
    it('accepts a 16-byte (128-bit) key', () => {
      const key = randomBytes(16).toString('base64');
      expect(() => validateEncryptionKey(key)).not.toThrow();
    });

    it('accepts a 24-byte (192-bit) key', () => {
      const key = randomBytes(24).toString('base64');
      expect(() => validateEncryptionKey(key)).not.toThrow();
    });

    it('accepts a 32-byte (256-bit) key', () => {
      const key = randomBytes(32).toString('base64');
      expect(() => validateEncryptionKey(key)).not.toThrow();
    });

    it('throws for a 10-byte key with a descriptive message', () => {
      const key = randomBytes(10).toString('base64');
      expect(() => validateEncryptionKey(key)).toThrow(
        'PARAMETER_ENCRYPTION_KEY must be a base64 string decoding to 16, 24, or 32 bytes; got 10 bytes'
      );
    });

    it('throws for a 1-byte key', () => {
      const key = randomBytes(1).toString('base64');
      expect(() => validateEncryptionKey(key)).toThrow(
        'PARAMETER_ENCRYPTION_KEY must be a base64 string decoding to 16, 24, or 32 bytes; got 1 bytes'
      );
    });

    it('throws for an empty string (0 bytes)', () => {
      expect(() => validateEncryptionKey('')).toThrow(
        'PARAMETER_ENCRYPTION_KEY must be a base64 string decoding to 16, 24, or 32 bytes; got 0 bytes'
      );
    });
  });
});
