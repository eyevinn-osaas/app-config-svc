import api from './api';

jest.mock('ioredis', () => {
  return {
    Redis: jest.fn().mockImplementation(() => {
      return {
        set: jest.fn().mockResolvedValue('OK'),
        get: jest.fn().mockResolvedValue('value'),
        del: jest.fn().mockResolvedValue(1),
        scan: jest.fn().mockResolvedValue(['0', []]),
        keys: jest.fn().mockResolvedValue([])
      };
    })
  };
});

describe('api', () => {
  it('responds with hello, world!', async () => {
    const server = api({
      title: 'my awesome service',
      redisUrl: new URL('redis://localhost:6379'),
      encryptionKey: Buffer.alloc(32).toString('base64'),
      configApiKey: 'test-api-key'
    });
    const response = await server.inject({
      method: 'GET',
      url: '/api'
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toBe('Hello, world! I am my awesome service');
  });
});
