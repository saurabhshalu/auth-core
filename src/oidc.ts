// src/oidc.ts
import express from "express";
import jwt from "jsonwebtoken";
import { createPublicKey } from "node:crypto";

import { getAxios } from "./utils/proxyAgent.js";
import { getDiscoveryForIssuer, sanitizeReturnTo } from "./utils/utilities.js";
import { resolveOidcForRequest } from "./utils/oidcRouter.js";

import type { Application, Request, Response } from "express";
import type {
  AuthConfig,
  AuthUser,
  JwtPayload,
  TokenSet,
  ResolvedOidc,
} from "./types.js";

// ── JWKS cache ────────────────────────────────────────────────────────────────

interface JwksEntry {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any;
  exp: number;
}

const JWKS_CACHE = new Map<string, JwksEntry>();
const JWKS_TTL = 10 * 60 * 1000;

// ── JWKS fetch ────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function fetchJwksForIssuer(
  issuer: string,
  config: AuthConfig,
): Promise<any> {
  const http = getAxios(config);
  const disc = await getDiscoveryForIssuer(issuer, config);
  const jwksUri = disc.jwksUri;
  const now = Date.now();
  const cached = JWKS_CACHE.get(jwksUri);
  if (cached && now < cached.exp) return cached.data;
  const { data } = await http.get(jwksUri);
  JWKS_CACHE.set(jwksUri, { data, exp: now + JWKS_TTL });
  return data;
}

// ── JWT verification ──────────────────────────────────────────────────────────

interface VerifyJwtOpts {
  issuer: string;
  expectedAlg?: string;
  audienceOverride?: string;
  skipAudience?: boolean;
}

async function verifyJwt(
  token: string,
  config: AuthConfig,
  opts: VerifyJwtOpts,
): Promise<JwtPayload> {
  const { issuer, expectedAlg, audienceOverride, skipAudience } = opts;
  if (!issuer) throw new Error("verifyJwt: issuer is required");

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded?.header) throw new Error("Invalid JWT");

  const jwks = await fetchJwksForIssuer(issuer, config);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let jwk = ((jwks.keys as any[]) ?? []).find(
    (k: any) => k.kid === decoded.header.kid,
  );

  if (!jwk) {
    // Refresh once on kid miss
    const disc = await getDiscoveryForIssuer(issuer, config);
    JWKS_CACHE.delete(disc.jwksUri);
    const refreshed = await fetchJwksForIssuer(issuer, config);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    jwk = ((refreshed.keys as any[]) ?? []).find(
      (k: any) => k.kid === decoded.header.kid,
    );
    if (!jwk) throw new Error("No matching JWK found for token kid");
  }

  const keyObj = createPublicKey({ key: jwk, format: "jwk" });
  const alg = expectedAlg ?? config.oidc?.algorithm ?? "RS256";

  const verifyOpts: jwt.VerifyOptions = {
    algorithms: [alg as jwt.Algorithm],
    issuer,
  };

  const shouldVerifyAud = !skipAudience && shouldVerifyAudience(config);
  if (shouldVerifyAud && audienceOverride) {
    verifyOpts.audience = audienceOverride;
  }

  const payload = jwt.verify(token, keyObj, verifyOpts);
  return payload as JwtPayload;
}

function shouldVerifyAudience(config: AuthConfig): boolean {
  const v =
    config.oidc?.verifyAudience ?? process.env["AUTH_CORE_VERIFY_AUDIENCE"];
  return String(v) === "true" || v === true;
}

// ── Token refresh ─────────────────────────────────────────────────────────────

export async function refreshToken(
  req: Request,
  config: AuthConfig,
): Promise<TokenSet> {
  const common = config.common ?? {};
  const active = req.session?.activeOidc ?? {};
  const issuer = active.issuer ?? config.oidc!.issuer!;
  const clientId = active.clientId ?? config.oidc!.clientId!;

  if (!req.session?.tokens?.refresh_token) throw new Error("No refresh token");

  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: req.session.tokens.refresh_token,
    client_id: clientId,
  });
  const clientSecret = active.clientSecret ?? config.oidc?.clientSecret;
  if (clientSecret) params.append("client_secret", clientSecret);

  const http = getAxios(config);
  const { tokenEndpoint } = await getDiscoveryForIssuer(issuer, config);
  const tokenResp = await http.post(tokenEndpoint, params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });

  const tokens = tokenResp.data as TokenSet;
  const accessPayload = await verifyJwt(tokens.access_token, config, {
    issuer,
    expectedAlg: active.algorithm ?? config.oidc?.algorithm ?? "RS256",
    audienceOverride:
      active.expectedAudience ?? active.clientId ?? config.oidc?.clientId,
  });

  const roles = [
    ...(accessPayload.roles ?? []),
    ...(accessPayload.realm_access?.roles ?? []),
  ];
  const resourceRoles =
    ((accessPayload.resource_access ?? {})[clientId] ?? { roles: [] }).roles ??
    [];
  roles.push(...resourceRoles);

  const updatedUser: AuthUser = {
    ...(req.session.user ?? { username: "", roles: [] }),
    roles,
    raw: accessPayload,
  };

  req.session.tokens = tokens;
  req.session.user = updatedUser;

  // ── Hooks ──────────────────────────────────────────────────────────────────
  const hooks = (req.app.locals as { authHooks?: AuthConfig["hooks"] })
    .authHooks;
  if (typeof hooks?.afterTokensVerified === "function") {
    try {
      // Need to verify id_token if present in refresh response
      let idPayload = {};
      if (tokens.id_token) {
        idPayload = await verifyJwt(tokens.id_token as string, config, {
          issuer,
          expectedAlg: active.algorithm ?? config.oidc?.algorithm ?? "RS256",
          audienceOverride: active.clientId ?? config.oidc?.clientId,
        });
      }

      const r = await hooks.afterTokensVerified({
        req,
        providerKey: active.clientKey ?? "primary",
        provider: { ...active } as ResolvedOidc,
        tokens,
        idPayload,
        accessPayload,
        intent: req.session.pending?.intent,
      });

      if (r?.userPatch) {
        req.session.user = { ...req.session.user, ...r.userPatch };
      }
    } catch (e) {
      console.error("[oidc][refresh] afterTokensVerified hook error:", e);
    }
  }

  // ── Global Enrichment (Conditional) ────────────────────────────────────────
  if (common.reEnrichOnRefresh !== false && typeof config.enrichSession === "function") {
    try {
      await config.enrichSession(req.session);
      req.session._enriched = true;
    } catch (err) {
      console.error("[oidc][refresh] enrichSession error:", err);
    }
  }

  // Final save to ensure everything (tokens + user + enrichment) is persisted
  await new Promise<void>((resolve) => {
    req.session.save(() => resolve());
  });

  return tokens;
}

// ── Bearer token auth (stateless) ────────────────────────────────────────────

export async function authenticateBearerToken(
  req: Request,
  config: AuthConfig,
): Promise<{ user: AuthUser } | null> {
  const common = config.common ?? {};
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return null;

  const token = auth.slice("Bearer ".length).trim();
  if (!token) return null;

  const { oidc: expectedOidc } = resolveOidcForRequest(req, config);
  if (!expectedOidc?.issuer || !expectedOidc?.clientId) {
    throw new Error("No OIDC configuration resolved for request path");
  }

  const decoded = jwt.decode(token);
  if (!decoded || typeof decoded !== "object") throw new Error("Invalid JWT");

  const tokenIssuer = (decoded as JwtPayload).iss?.replace(/\/+$/, "") ?? "";
  const expectedIssuer = expectedOidc.issuer.replace(/\/+$/, "");
  if (tokenIssuer !== expectedIssuer) {
    throw new Error("Token issuer not allowed for this path");
  }

  const payload = await verifyJwt(token, config, {
    issuer: expectedIssuer,
    expectedAlg: expectedOidc.algorithm ?? "RS256",
    audienceOverride: expectedOidc.expectedAudience ?? expectedOidc.clientId,
  });

  // Hard audience check
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const expectedAud = expectedOidc.expectedAudience ?? expectedOidc.clientId;
  if (!aud.includes(expectedAud)) throw new Error("Invalid token audience");

  const roles = [
    ...(payload.roles ?? []),
    ...(payload.realm_access?.roles ?? []),
  ];
  const resourceRoles =
    ((payload.resource_access ?? {})[expectedOidc.clientId] ?? {}).roles ?? [];
  roles.push(...resourceRoles);

  const user: AuthUser = {
    username: payload.preferred_username ?? payload.email ?? payload.sub ?? "",
    email: payload.email ?? null,
    roles,
    raw: payload,
  };

  // ── Hooks (Conditional) ─────────────────────────────────────────────────────
  const hooks = (req.app.locals as { authHooks?: AuthConfig["hooks"] }).authHooks;
  if (common.statelessHooks !== false && typeof hooks?.afterTokensVerified === "function") {
    try {
      const r = await hooks.afterTokensVerified({
        req,
        providerKey: "stateless", // No specific key for bearer tokens
        provider: expectedOidc as ResolvedOidc,
        tokens: { access_token: token }, // Partial token set
        idPayload: decoded, // Use decoded payload as idPayload for bearer
        accessPayload: payload,
        intent: "stateless_auth",
      });

      if (r?.userPatch) {
        Object.assign(user, r.userPatch);
      }
    } catch (e) {
      console.error("[oidc][bearer] afterTokensVerified hook error:", e);
    }
  }

  return { user };
}

// ── OIDC route setup ──────────────────────────────────────────────────────────

const PENDING_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes

export function setupOidc(app: Application, config: AuthConfig): void {
  const common = config.common ?? {};
  const baseOidc = config.oidc ?? {};
  const hooks =
    (app.locals as { authHooks?: AuthConfig["hooks"] }).authHooks ?? {};
  const appBase = common.appBasePath ?? "";

  // ── Callback ───────────────────────────────────────────────────────────────
  app.get(`${appBase}/callback`, async (req: Request, res: Response) => {
    try {
      const code = req.query["code"] as string | undefined;
      if (!code) return res.status(400).send("Missing code");

      const pending = req.session.pending;
      const state = req.query["state"] as string | undefined;

      if (!state || !pending?.state || state !== pending.state) {
        return res.status(400).send("Invalid state");
      }

      // ✅ FIX: Check pending session age to prevent replay attacks
      if (Date.now() - (pending.createdAt ?? 0) > PENDING_MAX_AGE_MS) {
        return res.status(400).send("Login session expired. Please try again.");
      }

      const eff: ResolvedOidc = pending.oidc
        ? {
            issuer: pending.oidc.issuer,
            clientId: pending.oidc.clientId,
            clientSecret: pending.oidc.clientSecret ?? null,
            expectedAudience:
              pending.oidc.expectedAudience ?? pending.oidc.clientId,
            redirectUri: pending.oidc.redirectUri!,
            includeLogoutClientId: !!pending.oidc.includeLogoutClientId,
            algorithm: pending.oidc.algorithm ?? "RS256",
            scope: baseOidc.scope ?? "openid profile email",
            verifyAudience: baseOidc.verifyAudience,
            enablePKCE: baseOidc.enablePKCE ?? true,
            codeChallengeMethod: baseOidc.codeChallengeMethod ?? "S256",
          }
        : {
            issuer: baseOidc.issuer!,
            clientId: baseOidc.clientId!,
            clientSecret: baseOidc.clientSecret ?? null,
            expectedAudience: baseOidc.expectedAudience ?? baseOidc.clientId!,
            redirectUri: baseOidc.redirectUri!,
            includeLogoutClientId: !!baseOidc.includeLogoutClientId,
            algorithm: baseOidc.algorithm ?? "RS256",
            scope: baseOidc.scope ?? "openid profile email",
            verifyAudience: baseOidc.verifyAudience,
            enablePKCE: baseOidc.enablePKCE ?? true,
            codeChallengeMethod: baseOidc.codeChallengeMethod ?? "S256",
          };

      // Token exchange
      const params = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: eff.redirectUri,
        client_id: eff.clientId,
      });
      if (eff.clientSecret) params.append("client_secret", eff.clientSecret);
      if (pending.pkceVerifier)
        params.append("code_verifier", pending.pkceVerifier);

      const http = getAxios(config);
      const { tokenEndpoint } = await getDiscoveryForIssuer(eff.issuer, config);
      const tokenResp = await http.post(tokenEndpoint, params, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      const tokens = tokenResp.data as TokenSet;
      if (!tokens.id_token) throw new Error("Missing id_token in OIDC response");

      // Quick nonce check pre-regenerate (on unverified decode for early rejection)
      const idLite = jwt.decode(tokens.id_token as string) as JwtPayload | null;
      if (!idLite) return res.status(400).send("Invalid ID token");
      if (!pending?.nonce || idLite.nonce !== pending.nonce) {
        return res.status(400).send("Invalid nonce");
      }

      await new Promise<void>((resolve, reject) =>
        req.session.regenerate((err) => (err ? reject(err) : resolve())),
      );

      // Verify tokens
      const idPayload = await verifyJwt(tokens.id_token as string, config, {
        issuer: eff.issuer,
        expectedAlg: eff.algorithm ?? "RS256",
        audienceOverride: eff.expectedAudience,
      });
      const accessPayload = await verifyJwt(tokens.access_token, config, {
        issuer: eff.issuer,
        expectedAlg: eff.algorithm ?? "RS256",
        audienceOverride: eff.expectedAudience,
      });

      // Re-validate nonce on verified payload
      if (idPayload.nonce !== pending.nonce) {
        return res.status(400).send("Invalid nonce (post-verify)");
      }

      // Build user
      let opId = accessPayload.opId ?? common.opId ?? "HOB";
      let buId = accessPayload.buId ?? common.buId ?? "DEFAULT";
      let language = accessPayload.language ?? common.language ?? "ENG";

      const organization = Object.keys(accessPayload.organization ?? {})[0];
      if (organization && accessPayload.organization) {
        const myOrg = accessPayload.organization[organization];
        if (myOrg?.opId) opId = myOrg.opId[0] ?? opId;
        if (myOrg?.buId) buId = myOrg.buId[0] ?? buId;
        if (myOrg?.language) language = myOrg.language[0] ?? language;
      }

      const effClientId = eff.clientId;
      const roles = [...(accessPayload.realm_access?.roles ?? [])];
      const resourceRoles =
        ((accessPayload.resource_access ?? {})[effClientId] ?? { roles: [] })
          .roles ?? [];
      roles.push(...resourceRoles);

      const user: AuthUser = {
        username:
          idPayload.preferred_username ??
          idPayload.email ??
          idPayload.sub ??
          "",
        firstName: idPayload.given_name,
        lastName: idPayload.family_name,
        email: idPayload.email ?? null,
        roles,
        organization,
        opId,
        buId,
        language,
        raw: accessPayload,
      };

      req.session.tokens = tokens;
      req.session.user = { ...user };
      req.session.activeOidc = {
        issuer: eff.issuer,
        clientId: eff.clientId,
        clientSecret: eff.clientSecret ?? null,
        expectedAudience: eff.expectedAudience ?? eff.clientId,
        redirectUri: eff.redirectUri,
        includeLogoutClientId: !!eff.includeLogoutClientId,
        algorithm: eff.algorithm ?? "RS256",
        clientKey: pending?.clientKey,
      };

      // Hooks
      let redirectOverride: string | null = null;
      if (typeof hooks.afterTokensVerified === "function") {
        try {
          const r = await hooks.afterTokensVerified({
            req,
            providerKey: pending?.clientKey ?? "primary",
            provider: { ...(req.session.activeOidc as ResolvedOidc) },
            tokens,
            idPayload,
            accessPayload,
            intent: pending?.intent,
          });
          if (r?.userPatch) {
            req.session.user = { ...req.session.user, ...r.userPatch };
          }
          if (r?.redirectTo) {
            redirectOverride = sanitizeReturnTo(r.redirectTo);
          }
        } catch (e) {
          console.error("[oidc] afterTokensVerified hook error:", e);
        }
      }

      delete req.session.pending;

      const defaultReturn = sanitizeReturnTo(
        req.session?.lastReturnTo ?? pending?.returnTo ?? common.appBasePath,
      );
      return res.redirect(redirectOverride ?? defaultReturn ?? "/");
    } catch (err) {
      console.error("[oidc] callback error:", err);
      res.status(500).send("Login failed");
    }
  });

  // ── RP-initiated logout ────────────────────────────────────────────────────
  app.get(`${appBase}/logout`, async (req: Request, res: Response) => {
    try {
      const active = req.session?.activeOidc ?? {};
      const issuer = active.issuer ?? config.oidc!.issuer!;
      const idToken = req.session?.tokens?.id_token;
      const redirectUri =
        common.postLogoutRedirectUri ?? common.appBasePath ?? "/";
      const { endSessionEndpoint } = await getDiscoveryForIssuer(
        issuer,
        config,
      );

      const includeLogoutClientId =
        active.includeLogoutClientId ??
        config.oidc?.includeLogoutClientId ??
        false;

      req.session.destroy(() => {
        if (endSessionEndpoint) {
          const params = new URLSearchParams({
            post_logout_redirect_uri: redirectUri,
          });
          if (idToken) params.set("id_token_hint", idToken);
          if (
            includeLogoutClientId &&
            (active.clientId ?? config.oidc?.clientId)
          ) {
            params.set("client_id", active.clientId ?? config.oidc!.clientId!);
          }
          return res.redirect(`${endSessionEndpoint}?${params.toString()}`);
        }
        return res.redirect(redirectUri);
      });
    } catch (e) {
      console.error("[oidc] logout error:", e);
      res.redirect(common.postLogoutRedirectUri ?? "/");
    }
  });

  // ── Backchannel logout ─────────────────────────────────────────────────────
  const urlencoded = express.urlencoded({ extended: false });
  app.post(
    `${appBase}/backchannel-logout`,
    urlencoded,
    async (req: Request, res: Response) => {
      try {
        const logoutToken = req.body.logout_token as string | undefined;
        if (!logoutToken) return res.status(400).send("Missing logout_token");

        const peek = jwt.decode(logoutToken) as JwtPayload | null;
        const issuer = peek?.iss ?? config.oidc!.issuer!;

        // ✅ FIX: Validate audience per OIDC Backchannel Logout spec §2.4
        const decoded = await verifyJwt(logoutToken, config, {
          issuer,
          expectedAlg:
            req.session?.activeOidc?.algorithm ??
            config.oidc?.algorithm ??
            "RS256",
          audienceOverride: config.oidc?.clientId,
          skipAudience: false,
        });

        const events = decoded.events ?? {};
        if (!events["http://schemas.openid.net/event/backchannel-logout"]) {
          return res.status(400).send("Invalid logout event");
        }

        // TODO (enhancement): index sessions by sub/sid in Redis for multi-pod logout
        req.session.destroy(() => res.sendStatus(200));
      } catch (err) {
        console.error("[oidc] backchannel-logout error:", err);
        res.sendStatus(400);
      }
    },
  );

  // ── Token refresh endpoint ─────────────────────────────────────────────────
  app.post(`${appBase}/token/refresh`, async (req: Request, res: Response) => {
    try {
      await refreshToken(req, config);
      res.send("OK");
    } catch (err) {
      console.error("[oidc] token refresh error:", err);
      res.status(500).send("Token Refresh failed");
    }
  });
}
