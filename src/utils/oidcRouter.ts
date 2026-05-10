// src/utils/oidcRouter.ts

import type { Request } from "express";
import type {
  AuthConfig,
  OidcConfig,
  PathClientMapping,
  PathClientMappingOidc,
  ResolvedOidc,
} from "../types.js";

/**
 * Merge an override OIDC config onto the base config.
 * Returns a fully-resolved, normalized ResolvedOidc.
 */
export function mergeOidc(
  base: OidcConfig,
  override: PathClientMappingOidc = {},
): ResolvedOidc {
  const o = override;

  const issuer = (o.issuer ?? base.issuer ?? "").replace(/\/+$/, "");
  if (!issuer)
    throw new Error("[auth] issuer must be provided in base or override");

  const clientId = o.clientId ?? o.client_id ?? base.clientId;
  if (!clientId) throw new Error("[auth] clientId is required");

  const clientSecret =
    o.clientSecret ?? o.client_secret ?? base.clientSecret ?? null;

  const redirectUri = o.redirectUri ?? o.redirect_uri ?? base.redirectUri;
  if (!redirectUri)
    throw new Error("[auth] redirectUri must be set in base or override");

  const expectedAudience =
    o.expectedAudience ??
    o.expected_audience ??
    base.expectedAudience ??
    clientId;

  return {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    scope: o.scope ?? base.scope ?? "openid profile email",
    algorithm: o.algorithm ?? base.algorithm ?? "RS256",
    verifyAudience: o.verifyAudience ?? base.verifyAudience,
    expectedAudience,
    includeLogoutClientId:
      o.includeLogoutClientId ?? base.includeLogoutClientId ?? false,
    enablePKCE: o.enablePKCE ?? base.enablePKCE ?? true,
    codeChallengeMethod:
      o.codeChallengeMethod ?? base.codeChallengeMethod ?? "S256",
  };
}

// ── matchesPattern ────────────────────────────────────────────────────────────

/**
 * Match a URL (pathname + searchParams) against a pattern string.
 *
 * Pattern syntax:
 *  - "*"                   → always true
 *  - "/path"               → exact path match
 *  - "/path/*"             → prefix match
 *  - "/path?key"           → path + key presence
 *  - "/path?key=val"       → path + exact key=val
 *  - "/path?key=a|b"       → path + one-of
 *  - "/path?key=*"         → path + any value (requires presence)
 *  - "/path?k1=v1&k2=v2"  → multiple constraints (AND)
 */
function matchesPattern(
  pattern: string,
  reqPath: string,
  reqSearchParams: URLSearchParams,
): boolean {
  if (pattern === "*") return true;

  // Prefix path (no query)
  if (pattern.endsWith("/*") && !pattern.includes("?")) {
    const prefix = pattern.slice(0, -2);
    return reqPath === prefix || reqPath.startsWith(prefix + "/");
  }

  const qIndex = pattern.indexOf("?");
  if (qIndex < 0) return reqPath === pattern;

  const pathPart = pattern.slice(0, qIndex);
  if (reqPath !== pathPart) return false;

  const queryPart = pattern.slice(qIndex + 1);
  if (!queryPart) return true;

  for (const pair of queryPart.split("&").filter(Boolean)) {
    const eqPos = pair.indexOf("=");

    if (eqPos === -1) {
      if (!reqSearchParams.has(pair)) return false;
      continue;
    }

    const key = pair.slice(0, eqPos);
    const rawVal = pair.slice(eqPos + 1);

    if (!reqSearchParams.has(key)) return false;

    const actual = reqSearchParams.get(key) ?? "";

    if (rawVal === "*") continue;

    if (rawVal.includes("|")) {
      if (!rawVal.split("|").includes(actual)) return false;
      continue;
    }

    if (rawVal === "") {
      if (actual !== "") return false;
      continue;
    }

    if (actual !== rawVal) return false;
  }

  return true;
}

// ── resolveOidcForRequest ─────────────────────────────────────────────────────

export interface ResolvedClient {
  clientKey: string;
  oidc: ResolvedOidc;
}

/**
 * Decide which OIDC (issuer + client) to use for this request.
 * Uses pathClientMappingList from config or AUTH_CORE_PATH_CLIENT_MAPPING_LIST env.
 * First match wins. Falls back to primary config.oidc.
 */
export function resolveOidcForRequest(
  req: Request,
  config: AuthConfig,
): ResolvedClient {
  const primary = config.oidc ?? {};
  const url = new URL(req.originalUrl, "http://local");
  const reqPath = url.pathname;
  const search = url.searchParams;

  let mapping: PathClientMapping[] | undefined =
    config.common?.pathClientMappingList;

  if (!mapping && process.env["AUTH_CORE_PATH_CLIENT_MAPPING_LIST"]) {
    try {
      mapping = JSON.parse(
        process.env["AUTH_CORE_PATH_CLIENT_MAPPING_LIST"]!,
      ) as PathClientMapping[];
    } catch {
      // ignore parse errors
    }
  }

  if (!Array.isArray(mapping) || mapping.length === 0) {
    return { clientKey: "primary", oidc: mergeOidc(primary) };
  }

  for (const item of mapping) {
    for (const p of item.paths ?? []) {
      if (matchesPattern(p, reqPath, search)) {
        const oidc = mergeOidc(primary, item.oidc ?? {});
        const clientKey =
          item.clientKey ??
          item.name ??
          item.oidc?.clientId ??
          item.oidc?.client_id ??
          "primary";
        return { clientKey, oidc };
      }
    }
  }

  return { clientKey: "primary", oidc: mergeOidc(primary) };
}
