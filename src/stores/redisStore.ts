// src/stores/redisStore.ts
//
// Helper for consumers who manage their own Redis client.
// If this store is passed into auth-core, auth-core will NOT close the connection.

import { createClient, type RedisClientType } from 'redis';
import { getRedisStoreCtor } from '../utils/sessionStoreAuto.js';
import type { Store } from 'express-session';
import type { Logger } from '../types.js';

export interface CreateRedisSessionStoreOptions {
  url: string;
  prefix?: string;
  ttlSeconds?: number;
  disableTTL?: boolean;
  socket?: Record<string, unknown>;
}

export interface RedisSessionStoreHandle {
  store: Store;
  client: RedisClientType;
  disconnect: () => Promise<void>;
}

export async function createRedisSessionStore(
  opts: CreateRedisSessionStoreOptions,
  logger: Logger = console
): Promise<RedisSessionStoreHandle> {
  const { url, prefix = 'sess:', ttlSeconds, disableTTL = false, socket } = opts;

  if (!url) throw new Error('[auth-core] createRedisSessionStore: `url` is required');

  const client = createClient({ url, socket }) as RedisClientType;
  client.on('error', (err: Error) =>
    logger?.error?.('[auth-core][redis] client error', err)
  );
  await client.connect();

  const storeOpts: Record<string, unknown> = { client, prefix };
  if (!disableTTL && typeof ttlSeconds === 'number') storeOpts['ttl'] = ttlSeconds;

  const RedisStore = await getRedisStoreCtor();
  const store      = new RedisStore(storeOpts);

  const disconnect = async (): Promise<void> => {
    try {
      if (client.isOpen) {
        await client.quit();
      }
    } catch (e) {
      logger?.error?.("[auth-core][redis] client closure failed:", e);
    }
  };

  return { store, client, disconnect };
}
