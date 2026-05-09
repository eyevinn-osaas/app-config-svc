import { Static, Type } from '@sinclair/typebox';
import fastifyAcceptsSerializer from '@fastify/accepts-serializer';
import { FastifyPluginCallback } from 'fastify';
import { ErrorReply, ErrorResponse, errorReply } from './api/errors';
import { Redis } from 'ioredis';
import { InvalidInputError, NotFoundError } from './utils/error';
import { encrypt, decrypt } from './crypto';

/**
 * Key prefix used for all parameter store entries in Valkey/Redis.
 * This prevents namespace collisions when an app shares the same Valkey
 * instance for its own data storage (sorted sets, hashes, etc.).
 */
export const KEY_PREFIX = 'osc:params:';

export interface ApiConfigOptions {
  redisUrl: URL;
  defaultCacheAge: number;
  encryptionKey?: string;
  configApiKey?: string;
}

/**
 * Envelope stored in Valkey for encrypted (secret) parameters.
 */
export interface SecretEnvelope {
  value: string;
  iv: string;
  tag: string;
  secret: true;
}

function isSecretEnvelope(
  raw: string
): raw is string & { __brand: 'envelope' } {
  try {
    const parsed = JSON.parse(raw);
    return (
      parsed !== null &&
      typeof parsed === 'object' &&
      parsed.secret === true &&
      typeof parsed.value === 'string' &&
      typeof parsed.iv === 'string' &&
      typeof parsed.tag === 'string'
    );
  } catch {
    return false;
  }
}

function parseEnvelope(raw: string): SecretEnvelope {
  return JSON.parse(raw) as SecretEnvelope;
}

export const ConfigObject = Type.Object({
  key: Type.String({ description: 'The key of the configuration object' }),
  value: Type.String({ description: 'The value of the configuration object' }),
  secret: Type.Optional(
    Type.Boolean({ description: 'Whether the value is a secret' })
  )
});
export type ConfigObject = Static<typeof ConfigObject>;

export const ConfigInput = Type.Object({
  key: Type.String({ description: 'The key of the configuration object' }),
  value: Type.String({ description: 'The value of the configuration object' }),
  secret: Type.Optional(
    Type.Boolean({ description: 'Whether the value is a secret' })
  )
});
export type ConfigInput = Static<typeof ConfigInput>;

export const ConfigUpdateInput = Type.Object({
  value: Type.String({ description: 'The new value' }),
  secret: Type.Optional(
    Type.Boolean({ description: 'Whether the value is a secret' })
  )
});
export type ConfigUpdateInput = Static<typeof ConfigUpdateInput>;

export const PageQuery = Type.Object({
  match: Type.Optional(Type.String()),
  offset: Type.Optional(Type.Number({ minimum: 0 })),
  limit: Type.Optional(Type.Number({ minimum: 1, maximum: 100 }))
});
export type PageQuery = Static<typeof PageQuery>;

export const ConfigObjectList = Type.Object({
  offset: Type.Number(),
  limit: Type.Number(),
  total: Type.Number(),
  items: Type.Array(ConfigObject)
});
export type ConfigObjectList = Static<typeof ConfigObjectList>;

export const SuccessResponse = Type.Object({
  message: Type.String({ description: 'Success message' })
});
export type SuccessResponse = Static<typeof SuccessResponse>;

const SECRET_MASK = '***';

/**
 * Given a raw stored string, return the ConfigObject for display (masked).
 * Secrets are returned with value '***'.
 */
function toDisplayObject(key: string, raw: string): ConfigObject {
  if (isSecretEnvelope(raw)) {
    return { key, value: SECRET_MASK, secret: true };
  }
  return { key, value: raw };
}

/**
 * Given a raw stored string, return the ConfigObject with plaintext decrypted.
 * Used for the authenticated config-to-env endpoint.
 * Caller must ensure encryptionKey is defined before calling with a secret value.
 */
function toPlaintextObject(
  key: string,
  raw: string,
  encryptionKey: string
): ConfigObject {
  if (isSecretEnvelope(raw)) {
    const envelope = parseEnvelope(raw);
    const plaintext = decrypt(
      envelope.value,
      envelope.iv,
      envelope.tag,
      encryptionKey
    );
    return { key, value: plaintext, secret: true };
  }
  return { key, value: raw };
}

/**
 * Read a key with lazy migration support.
 *
 * First checks for the prefixed key. If not found, falls back to the bare
 * (pre-migration) key. When a bare key is found, it is migrated in place:
 * the value is written under the prefixed key and the bare key is deleted.
 */
export async function getWithMigration(
  redis: Redis,
  key: string
): Promise<string | null> {
  let value = await redis.get(KEY_PREFIX + key);
  if (value === null) {
    // Fallback: check for bare key (pre-migration data)
    value = await redis.get(key);
    if (value !== null) {
      // Migrate in place: write prefixed, remove bare
      await redis.set(KEY_PREFIX + key, value);
      await redis.del(key);
    }
  }
  return value;
}

/**
 * Determine if the x-config-api-key header carries a valid key matching
 * the expected secret.
 * Returns false when expected is undefined (CONFIG_API_KEY not configured).
 */
function hasConfigApiKey(
  headerValue: string | undefined,
  expected: string | undefined
): boolean {
  if (!headerValue || !expected) return false;
  return headerValue === expected;
}

const apiConfig: FastifyPluginCallback<ApiConfigOptions> = (
  fastify,
  opts,
  next
) => {
  const redis = new Redis(opts.redisUrl.toString());

  fastify.setErrorHandler((error, request, reply) => {
    reply.code(500).send({ reason: error.message });
  });

  fastify.register(fastifyAcceptsSerializer);

  // POST /config — create a parameter (optionally secret)
  fastify.post<{ Body: ConfigInput; Reply: ConfigObject | ErrorResponse }>(
    '/config',
    {
      schema: {
        description: 'Create a new configuration object',
        body: ConfigInput,
        response: {
          200: ConfigObject,
          400: ErrorResponse,
          500: ErrorResponse
        }
      }
    },
    async (request, reply) => {
      try {
        const { key, value, secret } = request.body;
        let storedValue: string;

        if (secret) {
          if (!opts.encryptionKey) {
            return reply.code(400).send({
              reason:
                'Encryption not configured: PARAMETER_ENCRYPTION_KEY is required for secret parameters'
            });
          }
          const { encrypted, iv, tag } = encrypt(value, opts.encryptionKey);
          const envelope: SecretEnvelope = {
            value: encrypted,
            iv,
            tag,
            secret: true
          };
          storedValue = JSON.stringify(envelope);
          console.info(
            JSON.stringify({ key, secret: true, action: 'create' }),
            'Secret parameter created'
          );
        } else {
          storedValue = value;
        }

        const res = await redis.set(KEY_PREFIX + key, storedValue);
        if (res !== 'OK') {
          throw new InvalidInputError({ reason: 'Failed to set value' });
        }
        reply.code(200).send({
          key,
          value: secret ? SECRET_MASK : value,
          secret: secret || undefined
        });
      } catch (error) {
        errorReply(reply as ErrorReply, error);
      }
    }
  );

  // PUT /config/:key — update a parameter value (re-encrypt if secret)
  fastify.put<{
    Params: { key: string };
    Body: ConfigUpdateInput;
    Reply: ConfigObject | ErrorResponse;
  }>(
    '/config/:key',
    {
      schema: {
        description: 'Update an existing configuration object',
        body: ConfigUpdateInput,
        response: {
          200: ConfigObject,
          400: ErrorResponse,
          404: ErrorResponse,
          500: ErrorResponse
        }
      }
    },
    async (request, reply) => {
      try {
        const { key } = request.params;
        const { value, secret: newSecret } = request.body;

        const existing = await getWithMigration(redis, key);
        if (existing === null) {
          throw new NotFoundError({ id: key });
        }

        const wasSecret = isSecretEnvelope(existing);

        // Reject downgrade: secret -> non-secret
        if (wasSecret && newSecret === false) {
          throw new InvalidInputError({
            reason: 'Cannot convert a secret parameter to non-secret'
          });
        }

        // Determine effective secret flag: once secret, always secret
        const effectiveSecret = wasSecret || newSecret === true;

        let storedValue: string;
        if (effectiveSecret) {
          if (!opts.encryptionKey) {
            return reply.code(400).send({
              reason:
                'Encryption not configured: PARAMETER_ENCRYPTION_KEY is required for secret parameters'
            });
          }
          const { encrypted, iv, tag } = encrypt(value, opts.encryptionKey);
          const envelope: SecretEnvelope = {
            value: encrypted,
            iv,
            tag,
            secret: true
          };
          storedValue = JSON.stringify(envelope);
          console.info(
            JSON.stringify({ key, secret: true, action: 'update' }),
            'Secret parameter updated'
          );
        } else {
          storedValue = value;
        }

        const res = await redis.set(KEY_PREFIX + key, storedValue);
        if (res !== 'OK') {
          throw new InvalidInputError({ reason: 'Failed to update value' });
        }
        reply.code(200).send({
          key,
          value: effectiveSecret ? SECRET_MASK : value,
          secret: effectiveSecret || undefined
        });
      } catch (error) {
        errorReply(reply as ErrorReply, error);
      }
    }
  );

  // GET /config — list all parameters (masked), or plaintext for auth callers
  fastify.get<{
    Querystring: PageQuery;
    Reply: ConfigObjectList | ErrorResponse;
  }>(
    '/config',
    {
      schema: {
        description: 'Get all configuration objects in a paginated list',
        querystring: PageQuery,
        response: {
          200: ConfigObjectList,
          500: ErrorResponse
        }
      }
    },
    async (request, reply) => {
      try {
        const authenticated =
          !!opts.encryptionKey &&
          hasConfigApiKey(
            request.headers['x-config-api-key'] as string | undefined,
            opts.configApiKey
          );

        const limit = request.query.limit || 20;
        const cursor = request.query.offset || 0;
        const matchPattern = request.query.match
          ? KEY_PREFIX + request.query.match
          : KEY_PREFIX + '*';

        // Scan for prefixed keys (current format)
        const [newCursor, prefixedPageKeys] = await redis.scan(
          cursor,
          'MATCH',
          matchPattern,
          'COUNT',
          limit
        );

        // Scan for bare legacy keys (pre-migration format), excluding anything
        // that already starts with the prefix
        const [, allKeys] = await redis.scan(0, 'MATCH', '*', 'COUNT', 1000);
        const bareKeys = allKeys.filter(
          (k) =>
            !k.startsWith(KEY_PREFIX) &&
            (request.query.match
              ? k.match(
                  new RegExp(
                    '^' + request.query.match.replace(/\*/g, '.*') + '$'
                  )
                )
              : true)
        );

        // Migrate bare keys in place and collect their values
        const bareItems: ConfigObject[] = [];
        for (const bareKey of bareKeys) {
          const value = await redis.get(bareKey);
          if (value !== null) {
            await redis.set(KEY_PREFIX + bareKey, value);
            await redis.del(bareKey);
            bareItems.push(
              authenticated && opts.encryptionKey
                ? toPlaintextObject(bareKey, value, opts.encryptionKey)
                : toDisplayObject(bareKey, value)
            );
          }
        }

        // Collect values for the prefixed page keys
        const prefixedItems: ConfigObject[] = [];
        for (const k of prefixedPageKeys) {
          const value = await redis.get(k);
          if (value) {
            const itemKey = k.slice(KEY_PREFIX.length);
            prefixedItems.push(
              authenticated && opts.encryptionKey
                ? toPlaintextObject(itemKey, value, opts.encryptionKey)
                : toDisplayObject(itemKey, value)
            );
          }
        }

        // Total: count all prefixed keys (post-migration) plus any remaining bare keys
        const prefixedKeys = await redis.keys(KEY_PREFIX + '*');
        const total = prefixedKeys.length;

        const items = [...prefixedItems, ...bareItems];
        reply.code(200).send({
          offset: parseInt(newCursor),
          limit: items.length > limit ? items.length : limit,
          total,
          items
        });
      } catch (err) {
        errorReply(reply as ErrorReply, err);
      }
    }
  );

  // GET /config/:key — get a single parameter (masked), or plaintext for auth callers
  fastify.get<{
    Params: { key: string };
    Reply: ConfigObject | ErrorResponse;
  }>(
    '/config/:key',
    {
      config: {
        serializers: [
          {
            regex: /^text\/plain$/,
            serializer: (data: ConfigObject) => {
              return data.value;
            }
          }
        ]
      },
      schema: {
        description: 'Get a configuration object by key',
        response: {
          200: ConfigObject,
          404: ErrorResponse,
          500: ErrorResponse
        }
      }
    },
    async (request, reply) => {
      try {
        const authenticated =
          !!opts.encryptionKey &&
          hasConfigApiKey(
            request.headers['x-config-api-key'] as string | undefined,
            opts.configApiKey
          );

        const raw = await getWithMigration(redis, request.params.key);
        if (!raw) {
          throw new NotFoundError({ id: request.params.key });
        }

        const result =
          authenticated && opts.encryptionKey
            ? toPlaintextObject(request.params.key, raw, opts.encryptionKey)
            : toDisplayObject(request.params.key, raw);

        reply
          .code(200)
          .header('Cache-Control', `max-age=${opts.defaultCacheAge}`)
          .send(result);
      } catch (error) {
        errorReply(reply as ErrorReply, error);
      }
    }
  );

  // DELETE /config/:key
  fastify.delete<{
    Params: { key: string };
    Reply: SuccessResponse | ErrorResponse;
  }>(
    '/config/:key',
    {
      schema: {
        description: 'Delete a configuration object by key',
        response: {
          200: SuccessResponse,
          404: ErrorResponse,
          500: ErrorResponse
        }
      }
    },
    async (request, reply) => {
      try {
        const raw = await getWithMigration(redis, request.params.key);
        if (!raw) {
          throw new NotFoundError({ id: request.params.key });
        }

        if (isSecretEnvelope(raw)) {
          console.info(
            JSON.stringify({
              key: request.params.key,
              secret: true,
              action: 'delete'
            }),
            'Secret parameter deleted'
          );
        }

        // At this point the key has been migrated (if it was bare), so always
        // delete the prefixed version.
        await redis.del(KEY_PREFIX + request.params.key);
        reply.code(200).send({ message: 'Deleted' });
      } catch (error) {
        errorReply(reply as ErrorReply, error);
      }
    }
  );

  next();
};

export default apiConfig;
