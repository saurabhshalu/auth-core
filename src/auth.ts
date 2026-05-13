// src/auth.ts
import session from "express-session";
import * as crypto from "node:crypto";
import { setupOidc, refreshToken, authenticateBearerToken } from "./oidc.js";
import { setupCas } from "./cas.js";
import { getProxyAgent } from "./utils/proxyAgent.js";
import DelegatingStore from "./utils/delegatingStore.js";
import {
  shouldAutoEnableRedis,
  ensureAutoStoreInit,
  shutdownAutoStore,
  sessionStoreReadinessGuard,
  getAutoStoreSnapshot,
} from "./utils/sessionStoreAuto.js";
import { buildLogger, requestLogger } from "./utils/logger.js";
import { resolveConfig, validateConfig } from "./utils/configResolver.js";
import { getDiscoveryForIssuer, sanitizeReturnTo } from "./utils/utilities.js";
import { resolveOidcForRequest } from "./utils/oidcRouter.js";

import type {
  Application,
  Request,
  Response,
  NextFunction,
  RequestHandler,
} from "express";
import type { AuthConfig, AuthUser } from "./types.js";

// ── Public re-export ──────────────────────────────────────────────────────────
export { resolveOidcForRequest } from "./utils/oidcRouter.js";

// ── Helpers & constants ───────────────────────────────────────────────────────

function getTokenRefreshBuffer(config: AuthConfig): number {
  return config.common?.tokenRefreshBufferMs ?? 60 * 1000;
}

function requireSecret(common: NonNullable<AuthConfig["common"]>): string {
  const secret = common.sessionSecret;
  const env = String(
    common.environment ?? process.env["NODE_ENV"] ?? "DEVELOPMENT",
  ).toUpperCase();

  if (!secret && env !== "DEVELOPMENT") {
    throw new Error(
      "[auth-core] sessionSecret is required in non-development environments",
    );
  }
  return secret ?? "dev-only-insecure-secret";
}

// ── setupAuth ─────────────────────────────────────────────────────────────────

/**
 * Bootstraps session, logging, store, and mounts protocol routes.
 * Exposes hooks via app.locals.authHooks.
 */
function setupAuth(
  app: Application,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rawConfig: Record<string, any>,
): void {
  if (!app || !rawConfig)
    throw new Error("[auth-core] app and config required");

  const config = resolveConfig(rawConfig);
  validateConfig(config);

  const common = (config["common"] ?? {}) as NonNullable<AuthConfig["common"]>;
  const log = buildLogger((config["logger"] as AuthConfig["logger"]) ?? null);

  // ── /health endpoint (before any middleware — k8s probes) ──────────────────
  const appBase = common.appBasePath ?? "";

  if (
    !common.disableHealthEndpoint &&
    !(app.locals as Record<string, unknown>)["__authcore_health_registered"]
  ) {
    const healthPath = `${appBase}${common.healthEndpointContext ?? "/_health"}`;
    app.get(healthPath, (_req: Request, res: Response) => {
      res.status(200).json({ status: "ok" });
    });
    (app.locals as Record<string, unknown>)["__authcore_health_registered"] =
      true;
  }

  // Request logger (once per app)
  if (
    !(app.locals as Record<string, unknown>)["__authcore_reqlog_registered"]
  ) {
    app.use(requestLogger(config["logger"] as AuthConfig["logger"]));
    (app.locals as Record<string, unknown>)["__authcore_reqlog_registered"] =
      true;
  }

  // Hooks
  (app.locals as Record<string, unknown>)["authHooks"] = config["hooks"] ?? {};

  // Proxy agent
  const agent = getProxyAgent(config as AuthConfig);
  if (agent) (app.locals as Record<string, unknown>)["proxyAgent"] = agent;

  const mode = String(common.authMode ?? "OIDC").toUpperCase();

  if (mode === "NONE") {
    log.info("[auth] AUTH_MODE=NONE → skipping authentication setup.");
    app.use((_req: Request, _res: Response, next: NextFunction) => next());
    return;
  }

  // ── Session store resolution ──────────────────────────────────────────────
  const providedStore = common.session?.store;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let finalStore: any;

  if (providedStore) {
    finalStore = providedStore;
    log.info("session.store = provided (external)");
  } else if (shouldAutoEnableRedis(config as AuthConfig)) {
    ensureAutoStoreInit(config as AuthConfig, log);

    if (
      !(app.locals as Record<string, unknown>)["__authcore_guard_registered"]
    ) {
      app.use(sessionStoreReadinessGuard(config as AuthConfig, log));
      (app.locals as Record<string, unknown>)["__authcore_guard_registered"] =
        true;
    }

    finalStore = new DelegatingStore(() => getAutoStoreSnapshot().store);

    const SHUTDOWN_KEY =
      "__authcore_shutdown_registered__" as unknown as symbol;
    if (!(globalThis as Record<symbol, unknown>)[SHUTDOWN_KEY]) {
      const shutdownHandler = async () => {
        await shutdownAutoStore(log);
      };
      process.once("SIGTERM", shutdownHandler);
      process.once("SIGINT", shutdownHandler);
      (globalThis as Record<symbol, unknown>)[SHUTDOWN_KEY] = true;
    }

    log.info("session.store = auto-redis (delegated)");
  } else {
    const env = String(
      common.environment ?? process.env["NODE_ENV"] ?? "DEVELOPMENT",
    ).toUpperCase();
    const allow =
      String(
        process.env["AUTH_CORE_ALLOW_MEMORY_STORE_IN_PROD"] ?? "",
      ).toLowerCase() === "true";

    if (env !== "DEVELOPMENT" && !allow) {
      throw new Error(
        "[auth-core] MemoryStore is not allowed in non-development. Provide a persistent session store.",
      );
    }
    if (env === "DEVELOPMENT") {
      log.info("[auth-core] Using MemoryStore (development).");
    } else {
      log.warn(
        "[auth-core] Using MemoryStore in non-development (override enabled).",
      );
    }
  }

  // ── Session middleware ─────────────────────────────────────────────────────
  // ── Session ─────────────────────────────────────────────────────────────────
  const sessionMiddleware = session({
    name: common.sessionName ?? "NSESSIONID",
    secret: requireSecret(common),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    store: finalStore,
    cookie: {
      httpOnly: true,
      secure: String(common.environment ?? "").toUpperCase() !== "DEVELOPMENT",
      sameSite: common.cookieSameSite ?? "lax",
      maxAge:
        common.sessionCookieMode === "persistent"
          ? (common.sessionIdleTimeoutMins ?? 15) * 60 * 1000
          : undefined,
    },
  });

  // ✅ True Stateless Support: Skip session middleware if Authorization header is present
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.headers.authorization?.toLowerCase().startsWith("bearer ")) {
      return next();
    }
    sessionMiddleware(req, res, async () => {
      // Session enrichment (once)
      if (
        req.session &&
        typeof config["enrichSession"] === "function" &&
        !req.session._enriched
      ) {
        try {
          await (config["enrichSession"] as AuthConfig["enrichSession"])!(
            req.session,
          );
          req.session._enriched = true;

          // Explicitly save to ensure persistence in stores like Redis
          await new Promise<void>((resolve, reject) => {
            req.session.save((err) => {
              if (err) {
                console.error("[auth-core] Manual session save failed:", err);
                reject(err);
              } else {
                resolve();
              }
            });
          });
        } catch (err) {
          console.error("[auth-core] Failed to enrich session:", err);
        }
      }
      next();
    });
  });

  // ── Protocol selection ─────────────────────────────────────────────────────
  if (mode === "OIDC") setupOidc(app, config as AuthConfig);
  else if (mode === "CAS") setupCas(app, config as AuthConfig);
  else throw new Error(`[auth-core] Unsupported authMode: ${mode}`);

  // ── /me endpoint ───────────────────────────────────────────────────────────
  const meAPI = async (req: Request, res: Response): Promise<void> => {
    try {
      const user = (req as any).user || req.session?.user;
      if (!user) {
        res.status(401).json({ error: "Not authenticated" });
        return;
      }

      const extraData =
        typeof config["enrichMe"] === "function"
          ? await (config["enrichMe"] as AuthConfig["enrichMe"])!(
              req.session || {},
            )
          : {};

      const userDetails = { ...user } as AuthUser & {
        raw?: unknown;
      };
      delete (userDetails as Record<string, unknown>)["raw"];
      res.json({ ...userDetails, ...extraData });
    } catch (error) {
      log.error("Error in ME api =>", error);
      res
        .status(500)
        .json({ error: "Failed to get the details, Please check logs" });
    }
  };

  const mePath = `${appBase}${common.meEndpointContext ?? "/me"}`;
  app.get(mePath, meAPI as RequestHandler);
  app.post(mePath, meAPI as RequestHandler);
}

// ── protect middleware ─────────────────────────────────────────────────────────

/**
 * Protect middleware — OIDC/CAS.
 * - Chooses issuer+client per request (pathClientMappingList / ENV).
 * - Generates state, nonce, PKCE; calls beforeAuthRedirect hook.
 * - Redirects to the authorization_endpoint for the chosen issuer.
 */
function protect(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rawConfig: Record<string, any>,
): RequestHandler {
  const config = resolveConfig(rawConfig);
  validateConfig(config);

  const appBase = String(
    (config["common"] as Record<string, unknown>)?.["appBasePath"] ?? "",
  );
  const common = (config["common"] ?? {}) as NonNullable<AuthConfig["common"]>;

  const internalPaths = [
    `${appBase}/callback`,
    `${appBase}/backchannel-logout`,
    `${appBase}/validate`,
    `${appBase}/cas/serviceValidate`,
    ...(common.excludePathFromProtect ?? []),
  ];
  const exclude = new Set(internalPaths);

  const buffer = getTokenRefreshBuffer(config as AuthConfig);

  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
    res.set("Expires", "0");

    if (exclude.has(req.path)) return next();

    // Bearer token (stateless)
    try {
      const bearer = await authenticateBearerToken(req, config as AuthConfig);
      if (bearer) {
        (req as Request & { auth?: unknown }).auth = {
          type: "bearer",
          user: bearer.user,
        };
        (req as Request & { user?: unknown }).user = bearer.user;
        return next();
      }
    } catch (err) {
      res.status(401).json({ error: (err as Error).message });
      return;
    }

    const mode = String(common.authMode ?? "OIDC").toUpperCase();
    let authenticated = false;

    if (mode === "CAS") {
      authenticated = !!req.session?.cas?.user;
    } else if (mode === "OIDC") {
      if (req.session?.user && req.session.tokens) {
        const raw = req.session.user.raw;
        const expiresAt = (raw?.exp ?? 0) * 1000;
        const now = Date.now();

        if (now >= expiresAt - buffer) {
          try {
            const refreshed = await refreshToken(req, config as AuthConfig);
            authenticated = !!refreshed;
          } catch (err) {
            console.error("[auth-core] Token refresh failed:", err);
            req.session.destroy(() => res.redirect(`${appBase}/logout`));
            return;
          }
        } else {
          authenticated = true;
        }
      }
    }

    if (!authenticated) {
      if (mode === "CAS") {
        const casLoginUrl = `${config["cas"]?.["serverPath"]}${
          config["cas"]?.["paths"]?.["login"] ?? "/login"
        }?service=${encodeURIComponent(req.originalUrl)}`;
        return res.redirect(casLoginUrl);
      } else if (mode === "OIDC") {
        const { clientKey, oidc: selectedOidc } = resolveOidcForRequest(
          req,
          config as AuthConfig,
        );
        const hooks =
          ((req.app?.locals as Record<string, unknown>)?.[
            "authHooks"
          ] as AuthConfig["hooks"]) ?? {};

        // Discover authorization endpoint
        let authorizationEndpoint: string;
        try {
          const disc = await getDiscoveryForIssuer(
            selectedOidc.issuer,
            config as AuthConfig,
          );
          authorizationEndpoint =
            disc.authorizationEndpoint ??
            `${selectedOidc.issuer}/protocol/openid-connect/auth`;
        } catch {
          authorizationEndpoint = `${selectedOidc.issuer}/protocol/openid-connect/auth`;
        }

        const state = crypto.randomBytes(32).toString("base64url");
        const nonce = crypto.randomBytes(16).toString("base64url");

        let intent = (req as Request & { __oidcInitialIntent?: string })
          .__oidcInitialIntent;
        let extraAuthParams: Record<string, string> = {};

        if (typeof hooks?.beforeAuthRedirect === "function") {
          try {
            const r = await hooks.beforeAuthRedirect({
              req,
              providerKey: clientKey,
              provider: selectedOidc,
              intent,
            });
            if (r?.persistIntent) intent = r.persistIntent;
            if (r?.extraAuthParams) extraAuthParams = r.extraAuthParams;
          } catch (e) {
            console.error("[auth] beforeAuthRedirect hook error:", e);
          }
        }

        // PKCE
        let codeVerifier: string | undefined;
        if (selectedOidc.enablePKCE) {
          codeVerifier = crypto.randomBytes(64).toString("base64url");
          const codeChallenge =
            (selectedOidc.codeChallengeMethod ?? "").toLowerCase() === "plain"
              ? codeVerifier
              : crypto
                  .createHash("sha256")
                  .update(codeVerifier)
                  .digest("base64url");
          extraAuthParams["code_challenge"] = codeChallenge;
          extraAuthParams["code_challenge_method"] =
            selectedOidc.codeChallengeMethod ?? "S256";
        }

        const returnTo = sanitizeReturnTo(req.originalUrl ?? "/");
        req.session.pending = {
          state,
          nonce,
          returnTo,
          intent: intent ?? null,
          pkceVerifier: codeVerifier ?? null,
          createdAt: Date.now(),
          clientKey,
          oidc: {
            issuer: selectedOidc.issuer,
            clientId: selectedOidc.clientId,
            clientSecret: selectedOidc.clientSecret ?? null,
            expectedAudience:
              selectedOidc.expectedAudience ?? selectedOidc.clientId,
            redirectUri: selectedOidc.redirectUri,
            includeLogoutClientId: !!selectedOidc.includeLogoutClientId,
            algorithm: selectedOidc.algorithm ?? "RS256",
          },
        };

        const params = new URLSearchParams({
          response_type: "code",
          client_id: selectedOidc.clientId,
          redirect_uri: selectedOidc.redirectUri,
          scope: selectedOidc.scope ?? "openid profile email",
          state,
          nonce,
        });
        for (const [k, v] of Object.entries(extraAuthParams)) {
          if (v != null) params.set(k, String(v));
        }

        return res.redirect(`${authorizationEndpoint}?${params.toString()}`);
      }
    }

    next();
  };
}

// ── setupAuthAsync ─────────────────────────────────────────────────────────────

/**
 * Optional explicit async setup that ensures auto-redis readiness before mounting.
 */
async function setupAuthAsync(
  app: Application,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rawConfig: Record<string, any>,
): Promise<void> {
  if (!app || !rawConfig)
    throw new Error("[auth-core] app and config required");

  const config = resolveConfig(rawConfig);
  validateConfig(config);

  const provided = (config["common"] as NonNullable<AuthConfig["common"]>)
    ?.session?.store;
  if (!provided && shouldAutoEnableRedis(config as AuthConfig)) {
    await ensureAutoStoreInit(
      config as AuthConfig,
      buildLogger(config["logger"] as AuthConfig["logger"]),
    );
  }
  return setupAuth(app, config);
}

// ── Exports ───────────────────────────────────────────────────────────────────

export { setupAuth, setupAuthAsync, protect };
export { getProxyAgent } from "./utils/proxyAgent.js";
