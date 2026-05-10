// src/utils/sessionStoreAuto.ts
import { createClient, type RedisClientType } from "redis";
import type { Store } from "express-session";
import type { AuthConfig, Logger } from "../types.js";

// ── RedisStore constructor resolution ─────────────────────────────────────────

type RedisStoreCtor = new (opts: Record<string, unknown>) => Store;

export async function getRedisStoreCtor(): Promise<RedisStoreCtor> {
  // connect-redis is ESM-only; dynamic import required.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mod: any = await import("connect-redis");

  if (
    mod?.default &&
    typeof mod.default === "function" &&
    mod.default.prototype
  )
    return mod.default as RedisStoreCtor;

  if (mod?.RedisStore && typeof mod.RedisStore === "function")
    return mod.RedisStore as RedisStoreCtor;

  if (mod?.default?.RedisStore && typeof mod.default.RedisStore === "function")
    return mod.default.RedisStore as RedisStoreCtor;

  throw new Error(
    "[auth-core] Unable to resolve RedisStore constructor from 'connect-redis' module shape.",
  );
}

// ── Auto-Redis singleton state ────────────────────────────────────────────────

type AutoStoreState = "idle" | "connecting" | "ready" | "failed";

let state: AutoStoreState = "idle";
let autoStore: Store | undefined;
let autoClient: RedisClientType | undefined;
let autoError: Error | undefined;
let initPromise: Promise<Store> | null = null;

/** TRUE if ENV asks to auto-enable Redis. */
export function shouldAutoEnableRedis(config: AuthConfig): boolean {
  const flag = String(
    process.env["AUTH_CORE_SESSION_STORE"] ?? "",
  ).toLowerCase();
  if (flag !== "redis") return false;
  const url =
    process.env["AUTH_CORE_REDIS_URL"] ?? config?.common?.session?.redis?.url;
  return !!url;
}

/**
 * Start async init (idempotent). Creates Redis client + connect-redis store.
 * auth-core owns the lifecycle only in auto mode.
 */
export function ensureAutoStoreInit(
  config: AuthConfig,
  logger: Logger = console,
): Promise<Store> | null {
  if (!shouldAutoEnableRedis(config)) return null;
  if (initPromise) return initPromise;

  const url =
    process.env["AUTH_CORE_REDIS_URL"] ?? config?.common?.session?.redis?.url;
  if (!url) return null;

  const prefix =
    process.env["AUTH_CORE_REDIS_PREFIX"] ??
    config?.common?.session?.redis?.prefix ??
    "sess:";

  const ttlRaw = process.env["AUTH_CORE_REDIS_TTL_SECONDS"];
  const ttlSeconds =
    ttlRaw != null && Number.isFinite(Number(ttlRaw))
      ? Number(ttlRaw)
      : undefined;

  state = "connecting";

  initPromise = (async (): Promise<Store> => {
    try {
      autoClient = createClient({ url }) as RedisClientType;
      autoClient.on("error", (e: Error) =>
        logger?.error?.("[auth-core][redis] client error", e),
      );
      await autoClient.connect();

      const storeOpts: Record<string, unknown> = { client: autoClient, prefix };
      if (typeof ttlSeconds === "number") storeOpts["ttl"] = ttlSeconds;

      const RedisStore = await getRedisStoreCtor();
      autoStore = new RedisStore(storeOpts);
      state = "ready";
      logger?.info?.("[auth-core] Redis auto-store ready", { prefix });
      return autoStore;
    } catch (err) {
      autoError = err as Error;
      state = "failed";
      logger?.error?.("[auth-core] Redis auto-store init failed", {
        error: (err as Error)?.message,
      });
      throw err;
    }
  })();

  return initPromise;
}

export function getAutoStoreSnapshot(): {
  state: AutoStoreState;
  store: Store | undefined;
  error: Error | undefined;
} {
  return { state, store: autoStore, error: autoError };
}

/**
 * Graceful Redis disconnect (auto mode only).
 */
export async function shutdownAutoStore(
  logger: Logger = console,
): Promise<void> {
  if (!autoClient) return;
  const client = autoClient;

  // Clear refs immediately so re-entrant calls are no-ops
  autoClient = undefined;
  autoStore = undefined;
  state = "idle";
  initPromise = null;

  try {
    if (client.isOpen) {
      await client.quit();
      logger?.info?.("[auth-core] Redis client disconnected cleanly");
    }
  } catch (e) {
    logger?.warn?.("[auth-core] Redis client closure failed", {
      error: (e as Error)?.message,
    });
  }
}

// ── Readiness guard middleware ────────────────────────────────────────────────

export function sessionStoreReadinessGuard(
  config: AuthConfig,
  logger: Logger = console,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): (req: any, res: any, next: () => void) => void {
  const env = String(
    config?.common?.environment ?? process.env["NODE_ENV"] ?? "development",
  ).toUpperCase();

  const defaultPolicy = env === "DEVELOPMENT" ? "fallback" : "fail";
  const policy = String(
    process.env["AUTH_CORE_SESSION_INIT_MODE"] ?? defaultPolicy,
  ).toLowerCase();

  if (!shouldAutoEnableRedis(config)) return (_req, _res, next) => next();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (_req: any, res: any, next: () => void) => {
    const { state: s, error } = getAutoStoreSnapshot();

    if (s === "ready") return next();

    if (s === "connecting") {
      if (policy === "fallback" && env === "DEVELOPMENT") return next();
      return res.status(503).json({ error: "Session store initializing" });
    }

    if (s === "failed") {
      logger?.error?.("[auth-core] Redis store failed:", error?.message);
      if (policy === "fallback" && env === "DEVELOPMENT") return next();
      return res
        .status(503)
        .json({ error: "Session store unavailable (Redis init failed)" });
    }

    // 'idle' — should not reach here if ensureAutoStoreInit was called
    return next();
  };
}
