// src/cas.ts
import ConnectCas from "connect-cas2";
import jwt from "jsonwebtoken";

import type { Application, Request, Response, NextFunction } from "express";
import type { AuthConfig, AuthUser } from "./types.js";

// ── CAS token generation ──────────────────────────────────────────────────────

function generateCASAccessToken(
  userDetails: AuthUser,
  config: AuthConfig,
): string {
  const secret = config.cas?.tokenSecret ?? config.casTokenSecret;
  if (!secret) throw new Error("[auth-core] CAS token secret not configured");

  const ttlSeconds = config.cas?.tokenExpiresIn ?? 3600;

  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error(
      "[auth-core] CAS token expiry must be a positive integer",
    );
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: userDetails.username,
    preferred_username: userDetails.username,
    given_name: userDetails.firstName,
    family_name: userDetails.lastName,
    roles: userDetails.roles,
    opId: userDetails.opId,
    buId: userDetails.buId,
    email: userDetails.email,
    iat: now,
    exp: now + ttlSeconds,
  };

  return jwt.sign(payload, secret, { algorithm: "HS256" });
}

// ── setupCas ─────────────────────────────────────────────────────────────────

export function setupCas(app: Application, config: AuthConfig): void {
  const common = config.common ?? {};

  const casConfiguration = {
    ignore: config.cas?.ignore ?? [],
    match: config.cas?.match ?? [],
    servicePrefix: config.cas!.servicePrefix!,
    serverPath: config.cas!.serverPath!,
    paths: {
      login: "/login",
      logout: "/logout",
      validate: `${common.appBasePath ?? ""}/validate`,
      serviceValidate: "/serviceValidate",
      proxy: false as const,
      proxyCallback: false as const,
      ...(config.cas?.paths ?? {}),
    },
    slo: config.cas?.slo !== false,
    restletIntegration: false,
    ...(config.cas?.overrideConfiguration ?? {}),
  };

  const casClient = new ConnectCas(casConfiguration);
  app.use(casClient.core());

  // Normalize session: fetch user details on first CAS login
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    if (!req.session.cas || req.session.user) return next();

    const casData = req.session.cas as Record<string, any>;
    const user: AuthUser = {
      username: casData.user,
      roles: (casData.attributes?.roles as string[]) ?? [],
      firstName: (casData.attributes?.firstName as string) ?? undefined,
      lastName: (casData.attributes?.lastName as string) ?? undefined,
      email: (casData.attributes?.email as string) ?? null,
      raw: { ...casData },
    };

    req.session.user = user;
    next();
  });

  // Token refresh middleware: issue/refresh a synthetic CAS access token
  app.use((req: Request, _res: Response, next: NextFunction) => {
    const user = req.session?.user;
    if (!user) return next();

    const token = req.session?.tokens?.access_token;
    let needsRefresh = true;

    if (token) {
      try {
        const decoded = jwt.decode(token) as { exp?: number } | null;
        if (decoded?.exp) {
          const now = Math.floor(Date.now() / 1000);
          if (decoded.exp - now > 30) needsRefresh = false;
        }
      } catch {
        needsRefresh = true;
      }
    }

    if (needsRefresh) {
      req.session.tokens = {
        access_token: generateCASAccessToken(user, config),
        id_token: "", // CAS does not issue ID tokens; placeholder for type compat
      };
    }

    next();
  });

  // Logout
  app.get(
    `${common.appBasePath ?? ""}/logout`,
    (req: Request, res: Response) => {
      req.session.destroy(() => {
        const logoutUrl = `${config.cas!.serverPath}${casConfiguration.paths.logout}?service=${encodeURIComponent(
          common.postLogoutRedirectUri ?? "/",
        )}`;
        res.redirect(logoutUrl);
      });
    },
  );
}
