import fastifyStatic from '@fastify/static';
import path from 'path';
import api from './api';
import { validateEncryptionKey } from './crypto';

const redisUrl = new URL(process.env.REDIS_URL || 'redis://localhost:6379');
const defaultCacheAge = process.env.DEFAULT_CACHE_AGE
  ? Number(process.env.DEFAULT_CACHE_AGE)
  : undefined;
const encryptionKey = process.env.PARAMETER_ENCRYPTION_KEY;
const configApiKey = process.env.CONFIG_API_KEY;

if (encryptionKey) {
  try {
    validateEncryptionKey(encryptionKey);
  } catch (err) {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

const server = api({
  title: 'Application Configuration Service API',
  redisUrl,
  defaultCacheAge,
  encryptionKey,
  configApiKey
});

server.register(fastifyStatic, {
  root: path.join(__dirname, '../out'),
  prefix: '/'
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 8000;

server.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
  if (err) {
    throw err;
  }
  console.log(`Server listening on ${address}`);
});

export default server;
