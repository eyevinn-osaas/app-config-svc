import api from './api';
import { KEY_PREFIX } from './api_config';
import { encrypt } from './crypto';
import { randomBytes } from 'crypto';

// A key that decodes to 10 bytes (not a valid AES key length)
const BAD_ENCRYPTION_KEY = randomBytes(10).toString('base64');

// Fixed test encryption key (256-bit, base64)
const TEST_ENCRYPTION_KEY = randomBytes(32).toString('base64');

const mockPipeline = {
  type: jest.fn().mockReturnThis(),
  exec: jest.fn().mockResolvedValue([])
};

const mockRedis = {
  set: jest.fn().mockResolvedValue('OK'),
  get: jest.fn().mockResolvedValue('value'),
  del: jest.fn().mockResolvedValue(1),
  scan: jest.fn().mockResolvedValue(['0', []]),
  keys: jest.fn().mockResolvedValue([]),
  pipeline: jest.fn().mockReturnValue(mockPipeline)
};

jest.mock('ioredis', () => {
  return {
    Redis: jest.fn().mockImplementation(() => mockRedis)
  };
});

const TEST_CONFIG_API_KEY = 'test-api-key';

function makeServer() {
  return api({
    title: 'test',
    redisUrl: new URL('redis://localhost:6379'),
    encryptionKey: TEST_ENCRYPTION_KEY,
    configApiKey: TEST_CONFIG_API_KEY
  });
}

function makeServerNoEncryption() {
  return api({
    title: 'test',
    redisUrl: new URL('redis://localhost:6379')
    // encryptionKey and configApiKey intentionally omitted
  });
}

function makeServerBadKey() {
  return api({
    title: 'test',
    redisUrl: new URL('redis://localhost:6379'),
    encryptionKey: BAD_ENCRYPTION_KEY,
    configApiKey: TEST_CONFIG_API_KEY
  });
}

describe('api_config key prefix isolation', () => {
  let server: ReturnType<typeof makeServer>;

  beforeEach(() => {
    jest.clearAllMocks();
    // Default pipeline: one key, type=string (covers single-key listing tests)
    mockPipeline.type.mockReturnThis();
    mockPipeline.exec.mockResolvedValue([[null, 'string']]);
    server = makeServer();
  });

  describe('POST /api/v1/config', () => {
    it('stores keys with osc:params: prefix', async () => {
      mockRedis.set.mockResolvedValue('OK');

      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/config',
        payload: { key: 'mykey', value: 'myvalue' }
      });

      expect(response.statusCode).toBe(200);
      expect(mockRedis.set).toHaveBeenCalledWith(
        KEY_PREFIX + 'mykey',
        'myvalue'
      );
    });

    it('returns the original key (without prefix) in response', async () => {
      mockRedis.set.mockResolvedValue('OK');

      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/config',
        payload: { key: 'mykey', value: 'myvalue' }
      });

      const body = JSON.parse(response.body);
      expect(body.key).toBe('mykey');
    });

    it('stores a secret parameter as an encrypted JSON envelope', async () => {
      mockRedis.set.mockResolvedValue('OK');

      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/config',
        payload: { key: 'secretkey', value: 'topsecret', secret: true }
      });

      expect(response.statusCode).toBe(200);

      // The stored value must be a JSON envelope, not the raw plaintext
      const [, storedValue] = mockRedis.set.mock.calls[0] as [string, string];
      const envelope = JSON.parse(storedValue);
      expect(envelope.secret).toBe(true);
      expect(envelope.value).toBeDefined();
      expect(envelope.iv).toBeDefined();
      expect(envelope.tag).toBeDefined();
      // Raw plaintext must NOT be stored
      expect(storedValue).not.toContain('topsecret');
    });

    it('returns *** for secret value in response', async () => {
      mockRedis.set.mockResolvedValue('OK');

      const response = await server.inject({
        method: 'POST',
        url: '/api/v1/config',
        payload: { key: 'secretkey', value: 'topsecret', secret: true }
      });

      const body = JSON.parse(response.body);
      expect(body.value).toBe('***');
      expect(body.secret).toBe(true);
    });
  });

  describe('PUT /api/v1/config/:key', () => {
    it('updates a non-secret parameter value', async () => {
      mockRedis.get.mockResolvedValue('oldvalue');
      mockRedis.set.mockResolvedValue('OK');

      const response = await server.inject({
        method: 'PUT',
        url: '/api/v1/config/mykey',
        payload: { value: 'newvalue' }
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.key).toBe('mykey');
      expect(body.value).toBe('newvalue');
    });

    it('re-encrypts a secret parameter on update', async () => {
      // Simulate existing secret envelope in redis
      const existingEnvelope = JSON.stringify({
        value: encrypt('oldsecret', TEST_ENCRYPTION_KEY).encrypted,
        iv: encrypt('oldsecret', TEST_ENCRYPTION_KEY).iv,
        tag: encrypt('oldsecret', TEST_ENCRYPTION_KEY).tag,
        secret: true
      });
      mockRedis.get.mockResolvedValue(existingEnvelope);
      mockRedis.set.mockResolvedValue('OK');

      const response = await server.inject({
        method: 'PUT',
        url: '/api/v1/config/secretkey',
        payload: { value: 'newsecret' }
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.value).toBe('***');
      expect(body.secret).toBe(true);

      // Stored value must be a new envelope, not plaintext
      const [, storedValue] = mockRedis.set.mock.calls[0] as [string, string];
      const envelope = JSON.parse(storedValue);
      expect(envelope.secret).toBe(true);
      expect(storedValue).not.toContain('newsecret');
    });

    it('allows converting a non-secret to secret', async () => {
      mockRedis.get.mockResolvedValue('plainvalue');
      mockRedis.set.mockResolvedValue('OK');

      const response = await server.inject({
        method: 'PUT',
        url: '/api/v1/config/mykey',
        payload: { value: 'newvalue', secret: true }
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.value).toBe('***');
      expect(body.secret).toBe(true);
    });

    it('rejects converting a secret to non-secret (400)', async () => {
      const { encrypted, iv, tag } = encrypt('topsecret', TEST_ENCRYPTION_KEY);
      const existingEnvelope = JSON.stringify({
        value: encrypted,
        iv,
        tag,
        secret: true
      });
      mockRedis.get.mockResolvedValue(existingEnvelope);

      const response = await server.inject({
        method: 'PUT',
        url: '/api/v1/config/secretkey',
        payload: { value: 'plainvalue', secret: false }
      });

      expect(response.statusCode).toBe(400);
    });

    it('returns 404 when key does not exist', async () => {
      mockRedis.get.mockResolvedValue(null);

      const response = await server.inject({
        method: 'PUT',
        url: '/api/v1/config/nokey',
        payload: { value: 'v' }
      });

      expect(response.statusCode).toBe(404);
    });
  });

  describe('GET /api/v1/config/:key', () => {
    it('reads keys with osc:params: prefix', async () => {
      mockRedis.get.mockResolvedValue('myvalue');

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config/mykey'
      });

      expect(response.statusCode).toBe(200);
      expect(mockRedis.get).toHaveBeenCalledWith(KEY_PREFIX + 'mykey');
    });

    it('returns the original key (without prefix) in response', async () => {
      mockRedis.get.mockResolvedValue('myvalue');

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config/mykey'
      });

      const body = JSON.parse(response.body);
      expect(body.key).toBe('mykey');
      expect(body.value).toBe('myvalue');
    });

    it('returns *** for secret values without auth', async () => {
      const { encrypted, iv, tag } = encrypt('topsecret', TEST_ENCRYPTION_KEY);
      mockRedis.get.mockResolvedValue(
        JSON.stringify({ value: encrypted, iv, tag, secret: true })
      );

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config/secretkey'
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.value).toBe('***');
      expect(body.secret).toBe(true);
    });

    it('returns plaintext for secret values with valid x-config-api-key header', async () => {
      const { encrypted, iv, tag } = encrypt('topsecret', TEST_ENCRYPTION_KEY);
      mockRedis.get.mockResolvedValue(
        JSON.stringify({ value: encrypted, iv, tag, secret: true })
      );

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config/secretkey',
        headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.value).toBe('topsecret');
      expect(body.secret).toBe(true);
    });

    it('returns 404 when key does not exist', async () => {
      mockRedis.get.mockResolvedValue(null);

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config/nonexistent'
      });

      expect(response.statusCode).toBe(404);
      expect(mockRedis.get).toHaveBeenCalledWith(KEY_PREFIX + 'nonexistent');
    });

    it('falls back to bare key when prefixed key is absent and migrates in place', async () => {
      // First call (prefixed) returns null, second call (bare) returns value
      mockRedis.get
        .mockResolvedValueOnce(null) // KEY_PREFIX + 'legacykey'
        .mockResolvedValueOnce('legacyvalue'); // bare 'legacykey'

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config/legacykey'
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.key).toBe('legacykey');
      expect(body.value).toBe('legacyvalue');

      // Migration: prefixed key written, bare key deleted
      expect(mockRedis.set).toHaveBeenCalledWith(
        KEY_PREFIX + 'legacykey',
        'legacyvalue'
      );
      expect(mockRedis.del).toHaveBeenCalledWith('legacykey');
    });

    it('returns 404 when neither prefixed nor bare key exists', async () => {
      mockRedis.get.mockResolvedValue(null);

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config/missing'
      });

      expect(response.statusCode).toBe(404);
    });
  });

  describe('DELETE /api/v1/config/:key', () => {
    it('deletes keys with osc:params: prefix', async () => {
      mockRedis.get.mockResolvedValue('myvalue');
      mockRedis.del.mockResolvedValue(1);

      const response = await server.inject({
        method: 'DELETE',
        url: '/api/v1/config/mykey'
      });

      expect(response.statusCode).toBe(200);
      expect(mockRedis.get).toHaveBeenCalledWith(KEY_PREFIX + 'mykey');
      expect(mockRedis.del).toHaveBeenCalledWith(KEY_PREFIX + 'mykey');
    });

    it('returns 404 when deleting a key that does not exist', async () => {
      mockRedis.get.mockResolvedValue(null);

      const response = await server.inject({
        method: 'DELETE',
        url: '/api/v1/config/nonexistent'
      });

      expect(response.statusCode).toBe(404);
    });

    it('migrates bare key and deletes prefixed version when only bare key exists', async () => {
      // getWithMigration: prefixed lookup returns null, bare lookup returns value
      mockRedis.get
        .mockResolvedValueOnce(null) // KEY_PREFIX + 'legacykey'
        .mockResolvedValueOnce('legacyvalue'); // bare 'legacykey'
      mockRedis.del.mockResolvedValue(1);

      const response = await server.inject({
        method: 'DELETE',
        url: '/api/v1/config/legacykey'
      });

      expect(response.statusCode).toBe(200);
      // Migration writes prefixed key
      expect(mockRedis.set).toHaveBeenCalledWith(
        KEY_PREFIX + 'legacykey',
        'legacyvalue'
      );
      // Migration deletes bare key
      expect(mockRedis.del).toHaveBeenCalledWith('legacykey');
      // Final delete removes the (now-migrated) prefixed key
      expect(mockRedis.del).toHaveBeenCalledWith(KEY_PREFIX + 'legacykey');
    });
  });

  describe('GET /api/v1/config', () => {
    it('scans only keys matching the osc:params: prefix', async () => {
      mockRedis.scan
        .mockResolvedValueOnce(['0', [KEY_PREFIX + 'k1']]) // prefixed scan
        .mockResolvedValueOnce(['0', [KEY_PREFIX + 'k1']]); // all-keys scan
      mockRedis.keys.mockResolvedValue([KEY_PREFIX + 'k1']);
      mockRedis.get.mockResolvedValue('v1');

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config'
      });

      expect(response.statusCode).toBe(200);
      expect(mockRedis.scan).toHaveBeenCalledWith(
        0,
        'MATCH',
        KEY_PREFIX + '*',
        'COUNT',
        20
      );
    });

    it('strips prefix from keys returned in listing', async () => {
      mockRedis.scan
        .mockResolvedValueOnce(['0', [KEY_PREFIX + 'k1']]) // prefixed scan
        .mockResolvedValueOnce(['0', [KEY_PREFIX + 'k1']]); // all-keys scan
      mockRedis.keys.mockResolvedValue([KEY_PREFIX + 'k1']);
      mockRedis.get.mockResolvedValue('v1');

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config'
      });

      const body = JSON.parse(response.body);
      expect(body.items[0].key).toBe('k1');
    });

    it('applies match pattern with prefix prepended', async () => {
      mockRedis.scan
        .mockResolvedValueOnce(['0', []]) // prefixed scan
        .mockResolvedValueOnce(['0', []]); // all-keys scan
      mockRedis.keys.mockResolvedValue([]);

      await server.inject({
        method: 'GET',
        url: '/api/v1/config?match=foo*'
      });

      expect(mockRedis.scan).toHaveBeenCalledWith(
        0,
        'MATCH',
        KEY_PREFIX + 'foo*',
        'COUNT',
        20
      );
    });

    it('includes legacy bare keys in listing and migrates them', async () => {
      // First scan: prefixed keys page (empty for this test)
      // Second scan: all keys (returns a bare legacy key)
      mockRedis.scan
        .mockResolvedValueOnce(['0', []]) // prefixed MATCH scan
        .mockResolvedValueOnce(['0', ['legacykey']]); // all-keys scan
      mockRedis.keys.mockResolvedValue([KEY_PREFIX + 'legacykey']); // after migration
      mockRedis.get.mockResolvedValue('legacyvalue');

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config'
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.items).toEqual(
        expect.arrayContaining([{ key: 'legacykey', value: 'legacyvalue' }])
      );
      // Migrated: bare key written as prefixed and bare deleted
      expect(mockRedis.set).toHaveBeenCalledWith(
        KEY_PREFIX + 'legacykey',
        'legacyvalue'
      );
      expect(mockRedis.del).toHaveBeenCalledWith('legacykey');
    });

    it('masks secret values in listing when unauthenticated', async () => {
      const { encrypted, iv, tag } = encrypt('topsecret', TEST_ENCRYPTION_KEY);
      const envelope = JSON.stringify({
        value: encrypted,
        iv,
        tag,
        secret: true
      });

      mockRedis.scan
        .mockResolvedValueOnce(['0', [KEY_PREFIX + 'secretkey']])
        .mockResolvedValueOnce(['0', []]);
      mockRedis.keys.mockResolvedValue([KEY_PREFIX + 'secretkey']);
      mockRedis.get.mockResolvedValue(envelope);

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config'
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      const item = body.items.find(
        (i: { key: string }) => i.key === 'secretkey'
      );
      expect(item.value).toBe('***');
      expect(item.secret).toBe(true);
    });

    it('returns plaintext in listing with valid x-config-api-key header', async () => {
      const { encrypted, iv, tag } = encrypt('topsecret', TEST_ENCRYPTION_KEY);
      const envelope = JSON.stringify({
        value: encrypted,
        iv,
        tag,
        secret: true
      });

      mockRedis.scan
        .mockResolvedValueOnce(['0', [KEY_PREFIX + 'secretkey']])
        .mockResolvedValueOnce(['0', []]);
      mockRedis.keys.mockResolvedValue([KEY_PREFIX + 'secretkey']);
      mockRedis.get.mockResolvedValue(envelope);

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config',
        headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      const item = body.items.find(
        (i: { key: string }) => i.key === 'secretkey'
      );
      expect(item.value).toBe('topsecret');
    });

    it('skips non-String keys (Hash/List/Set) and returns skippedKeys count', async () => {
      // Seed: prefixedPageKeys has 2 string keys + 1 hash key
      const stringKey1 = KEY_PREFIX + 'strkey1';
      const stringKey2 = KEY_PREFIX + 'strkey2';
      const hashKey = KEY_PREFIX + 'hashkey';

      mockRedis.scan
        .mockResolvedValueOnce(['0', [stringKey1, stringKey2, hashKey]]) // prefixed scan
        .mockResolvedValueOnce(['0', []]); // all-keys scan (no bare keys)
      mockRedis.keys.mockResolvedValue([stringKey1, stringKey2, hashKey]);

      // Pipeline type check: string, string, hash
      mockPipeline.exec.mockResolvedValueOnce([
        [null, 'string'],
        [null, 'string'],
        [null, 'hash']
      ]);

      // redis.get called only for the 2 string keys
      mockRedis.get
        .mockResolvedValueOnce('value1')
        .mockResolvedValueOnce('value2');

      const response = await server.inject({
        method: 'GET',
        url: '/api/v1/config'
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.items).toHaveLength(2);
      expect(body.items.map((i: { key: string }) => i.key)).toEqual(
        expect.arrayContaining(['strkey1', 'strkey2'])
      );
      expect(body.skippedKeys).toBe(1);
      // redis.get must NOT have been called for the hash key
      expect(mockRedis.get).toHaveBeenCalledTimes(2);
    });
  });
});

describe('POST /api/v1/migrate/secure', () => {
  let server: ReturnType<typeof makeServer>;

  beforeEach(() => {
    jest.clearAllMocks();
    server = makeServer();
  });

  it('returns 401 when x-config-api-key header is missing', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: {}
    });

    expect(response.statusCode).toBe(401);
  });

  it('returns 401 when x-config-api-key header is wrong', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: {},
      headers: { 'x-config-api-key': 'wrong-key' }
    });

    expect(response.statusCode).toBe(401);
  });

  it('returns 400 when PARAMETER_ENCRYPTION_KEY is not configured', async () => {
    const serverNoEnc = api({
      title: 'test',
      redisUrl: new URL('redis://localhost:6379'),
      configApiKey: TEST_CONFIG_API_KEY
      // encryptionKey intentionally omitted
    });

    const response = await serverNoEnc.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: {},
      headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.reason).toMatch(/PARAMETER_ENCRYPTION_KEY/);
  });

  it('migrates plaintext keys to encrypted envelopes', async () => {
    // SCAN returns two prefixed keys
    mockRedis.scan.mockResolvedValueOnce([
      '0',
      [KEY_PREFIX + 'key1', KEY_PREFIX + 'key2']
    ]);
    // Both values are plaintext
    mockRedis.get
      .mockResolvedValueOnce('value1')
      .mockResolvedValueOnce('value2');
    mockRedis.set.mockResolvedValue('OK');

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: {},
      headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.migrated).toEqual(expect.arrayContaining(['key1', 'key2']));
    expect(body.skipped).toEqual([]);
    expect(body.dryRun).toBe(false);

    // redis.set must have been called twice (once per key)
    expect(mockRedis.set).toHaveBeenCalledTimes(2);

    // Stored value for key1 must be a valid encrypted envelope
    const [, storedValue1] = mockRedis.set.mock.calls[0] as [string, string];
    const envelope1 = JSON.parse(storedValue1);
    expect(envelope1.secret).toBe(true);
    expect(envelope1.value).toBeDefined();
    expect(envelope1.iv).toBeDefined();
    expect(envelope1.tag).toBeDefined();
    expect(storedValue1).not.toContain('value1');
  });

  it('skips keys that are already encrypted envelopes', async () => {
    const { encrypted, iv, tag } = encrypt('topsecret', TEST_ENCRYPTION_KEY);
    const existingEnvelope = JSON.stringify({
      value: encrypted,
      iv,
      tag,
      secret: true
    });

    mockRedis.scan.mockResolvedValueOnce([
      '0',
      [KEY_PREFIX + 'plain', KEY_PREFIX + 'secret']
    ]);
    mockRedis.get
      .mockResolvedValueOnce('plaintext') // plain key
      .mockResolvedValueOnce(existingEnvelope); // secret key
    mockRedis.set.mockResolvedValue('OK');

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: {},
      headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.migrated).toEqual(['plain']);
    expect(body.skipped).toEqual(['secret']);
    expect(body.dryRun).toBe(false);

    // Only the plaintext key should be written
    expect(mockRedis.set).toHaveBeenCalledTimes(1);
    expect(mockRedis.set.mock.calls[0][0]).toBe(KEY_PREFIX + 'plain');
  });

  it('dryRun=true returns correct lists but makes no writes to Redis', async () => {
    mockRedis.scan.mockResolvedValueOnce([
      '0',
      [KEY_PREFIX + 'key1', KEY_PREFIX + 'key2']
    ]);
    mockRedis.get
      .mockResolvedValueOnce('value1')
      .mockResolvedValueOnce('value2');

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: { dryRun: true },
      headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.migrated).toEqual(expect.arrayContaining(['key1', 'key2']));
    expect(body.skipped).toEqual([]);
    expect(body.dryRun).toBe(true);

    // No writes should have occurred
    expect(mockRedis.set).not.toHaveBeenCalled();
  });

  it('migrates only specified keys when keys array is provided', async () => {
    // Only key1 is requested — key2 is NOT in the request
    mockRedis.get.mockResolvedValueOnce('value1'); // for KEY_PREFIX + 'key1'
    mockRedis.set.mockResolvedValue('OK');

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: { keys: ['key1'] },
      headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.migrated).toEqual(['key1']);
    expect(body.skipped).toEqual([]);
    expect(body.dryRun).toBe(false);

    // SCAN must NOT have been called (explicit key list was provided)
    expect(mockRedis.scan).not.toHaveBeenCalled();

    // Only key1 should have been written
    expect(mockRedis.set).toHaveBeenCalledTimes(1);
    expect(mockRedis.set.mock.calls[0][0]).toBe(KEY_PREFIX + 'key1');
  });
});

describe('api_config without encryption keys (backward compatibility)', () => {
  let server: ReturnType<typeof makeServerNoEncryption>;

  beforeEach(() => {
    jest.clearAllMocks();
    server = makeServerNoEncryption();
  });

  it('starts and serves non-secret parameters without PARAMETER_ENCRYPTION_KEY', async () => {
    mockRedis.set.mockResolvedValue('OK');

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/config',
      payload: { key: 'mykey', value: 'myvalue' }
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.key).toBe('mykey');
    expect(body.value).toBe('myvalue');
  });

  it('returns 400 when POST requests secret:true without PARAMETER_ENCRYPTION_KEY', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/config',
      payload: { key: 'secretkey', value: 'topsecret', secret: true }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.reason).toMatch(/PARAMETER_ENCRYPTION_KEY/);
  });

  it('returns 400 when PUT upgrades to secret without PARAMETER_ENCRYPTION_KEY', async () => {
    mockRedis.get.mockResolvedValue('plainvalue');

    const response = await server.inject({
      method: 'PUT',
      url: '/api/v1/config/mykey',
      payload: { value: 'newvalue', secret: true }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.reason).toMatch(/PARAMETER_ENCRYPTION_KEY/);
  });

  it('returns 400 when PUT re-encrypts an existing secret without PARAMETER_ENCRYPTION_KEY', async () => {
    // Simulate a secret envelope that was stored when the key was configured
    const envelope = JSON.stringify({
      value: 'encryptedblob',
      iv: 'ivblob',
      tag: 'tagblob',
      secret: true
    });
    mockRedis.get.mockResolvedValue(envelope);

    const response = await server.inject({
      method: 'PUT',
      url: '/api/v1/config/secretkey',
      payload: { value: 'newsecret' }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.reason).toMatch(/PARAMETER_ENCRYPTION_KEY/);
  });

  it('returns masked value for plain GET without keys configured', async () => {
    mockRedis.get.mockResolvedValue('plainvalue');

    const response = await server.inject({
      method: 'GET',
      url: '/api/v1/config/mykey'
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.value).toBe('plainvalue');
  });
});

describe('api_config with invalid encryption key (RangeError protection)', () => {
  let server: ReturnType<typeof makeServerBadKey>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockPipeline.type.mockReturnThis();
    mockPipeline.exec.mockResolvedValue([[null, 'string']]);
    server = makeServerBadKey();
  });

  it('POST /api/v1/config returns HTTP 400 with actionable reason when key is invalid', async () => {
    mockRedis.set.mockResolvedValue('OK');

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/config',
      payload: { key: 'secretkey', value: 'topsecret', secret: true }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.reason).toMatch(/encryption key is invalid/);
    expect(body.reason).toMatch(/setup-parameter-store/);
  });

  it('PUT /api/v1/config/:key returns HTTP 400 with actionable reason when key is invalid', async () => {
    // Existing envelope that triggers the re-encrypt path
    const envelope = JSON.stringify({
      value: 'encryptedblob',
      iv: Buffer.alloc(12).toString('base64'),
      tag: Buffer.alloc(16).toString('base64'),
      secret: true
    });
    mockRedis.get.mockResolvedValue(envelope);

    const response = await server.inject({
      method: 'PUT',
      url: '/api/v1/config/secretkey',
      payload: { value: 'newsecret' }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.reason).toMatch(/encryption key is invalid/);
    expect(body.reason).toMatch(/setup-parameter-store/);
  });

  it('POST /api/v1/migrate/secure returns HTTP 400 with actionable reason when key is invalid', async () => {
    mockRedis.scan.mockResolvedValueOnce(['0', [KEY_PREFIX + 'plainkey']]);
    mockRedis.get.mockResolvedValueOnce('plainvalue');

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/migrate/secure',
      payload: {},
      headers: { 'x-config-api-key': TEST_CONFIG_API_KEY }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.reason).toMatch(/encryption key is invalid/);
    expect(body.reason).toMatch(/setup-parameter-store/);
  });
});
