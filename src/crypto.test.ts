import { encrypt, decrypt } from './crypto';
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
});
