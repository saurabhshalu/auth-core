// src/utils/logger.ts
import { randomBytes } from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import type { Logger } from "../types.js";

// Internal wrapped-logger shape

interface StructuredLogger {
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  event: (
    level: "debug" | "info" | "warn" | "error",
    msg: string,
    meta?: Record<string, unknown>,
  ) => void;
}

const WRAPPED_SYMBOL = Symbol.for("authcore.logger.wrapped");
const INSTANCE_SYMBOL = Symbol.for("authcore.logger.instance");

type AnyLogger = Logger & {
  [WRAPPED_SYMBOL]?: boolean;
  [INSTANCE_SYMBOL]?: StructuredLogger;
};

const REDACT_KEYS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "id_token",
  "access_token",
  "refresh_token",
]);

function redactObj(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = REDACT_KEYS.has(k.toLowerCase()) ? "[REDACTED]" : v;
  }
  return out;
}

function bind(
  base: AnyLogger,
  primary: keyof Logger,
  fallback: keyof Logger,
): (...args: unknown[]) => void {
  const fn = (base[primary] ?? base[fallback]) as
    | ((...args: unknown[]) => void)
    | undefined;
  return fn
    ? fn.bind(base)
    : () => {
        /* no-op */
      };
}

/**
 * Minimal structured logger adapter.
 * Wraps any console-like, pino, or winston logger.
 * Avoids double-wrapping via a Symbol mark.
 */
export function buildLogger(userLogger?: Logger | null): StructuredLogger {
  const base = (userLogger ?? console) as AnyLogger;

  if (base[INSTANCE_SYMBOL]) return base[INSTANCE_SYMBOL]!;

  const info = bind(base, "info", "log");
  const warn = bind(base, "warn", "log");
  const error = bind(base, "error", "log");
  const debug = bind(base, "debug", "log");

  const logger: StructuredLogger = {
    debug: (...a) => debug(...a),
    info: (...a) => info(...a),
    warn: (...a) => warn(...a),
    error: (...a) => error(...a),

    event(level, msg, meta = {}) {
      const safeMeta: Record<string, unknown> = { ...meta };
      if (safeMeta["headers"] && typeof safeMeta["headers"] === "object") {
        safeMeta["headers"] = redactObj(
          safeMeta["headers"] as Record<string, unknown>,
        );
      }
      if (safeMeta["tokens"] && typeof safeMeta["tokens"] === "object") {
        const t = safeMeta["tokens"] as Record<string, unknown>;
        safeMeta["tokens"] = {
          id_token: t["id_token"] ? "[REDACTED]" : undefined,
          access_token: t["access_token"] ? "[REDACTED]" : undefined,
          refresh_token: t["refresh_token"] ? "[REDACTED]" : undefined,
          ...Object.fromEntries(
            Object.entries(t).filter(
              ([k]) =>
                !["id_token", "access_token", "refresh_token"].includes(k),
            ),
          ),
        };
      }
      const sink = logger[level] ?? logger.info;
      sink(`[auth-core] ${msg}`, safeMeta);
    },
  };

  // Store both the flag and the adapter instance
  Object.defineProperty(base, WRAPPED_SYMBOL, {
    value: true,
    enumerable: false,
    configurable: true,
  });
  Object.defineProperty(base, INSTANCE_SYMBOL, {
    value: logger,
    enumerable: false,
    configurable: true,
  });
  return logger;
}

// ── Per-request logger middleware ────────────────────────────────────────────

interface RequestLoggerOptions {
  headerName?: string;
  generateId?: (req: Request) => string;
}

/**
 * Express middleware that attaches req.log and a per-request requestId.
 * Avoids re-attaching if already present.
 */
export function requestLogger(
  logger?: Logger | null,
  { headerName = "x-request-id", generateId }: RequestLoggerOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  const log = buildLogger(logger);

  return (req: Request, _res: Response, next: NextFunction) => {
    if (!(req as Request & { requestId?: string }).requestId) {
      let requestId: string =
        (req.headers?.[headerName] as string | undefined) ??
        (req as Request & { id?: string }).id ??
        "";
      if (!requestId && typeof generateId === "function")
        requestId = generateId(req);
      if (!requestId) requestId = randomBytes(8).toString("base64url");
      (req as Request & { requestId?: string }).requestId = requestId;
    }

    if (!(req as Request & { log?: unknown }).log) {
      const rid = (req as Request & { requestId?: string }).requestId!;
      (req as Request & { log?: unknown }).log = {
        debug: (msg: string, meta?: Record<string, unknown>) =>
          log.event("debug", msg, { requestId: rid, ...meta }),
        info: (msg: string, meta?: Record<string, unknown>) =>
          log.event("info", msg, { requestId: rid, ...meta }),
        warn: (msg: string, meta?: Record<string, unknown>) =>
          log.event("warn", msg, { requestId: rid, ...meta }),
        error: (msg: string, meta?: Record<string, unknown>) =>
          log.event("error", msg, { requestId: rid, ...meta }),
      };
      log.event("debug", "request.start", {
        requestId: rid,
        method: req.method,
        path: req.path,
      });
    }

    next();
  };
}
