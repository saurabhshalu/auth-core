// src/utils/utilities.ts
import { getAxios } from "./proxyAgent.js";
import type { AuthConfig } from "../types.js";

// ── Discovery cache ─────────────────────────────────────────────────────────

interface DiscoveryData {
  authorizationEndpoint?: string;
  tokenEndpoint: string;
  jwksUri: string;
  endSessionEndpoint?: string;
  issuer: string;
  userinfoEndpoint?: string;
}

interface CacheEntry {
  data: DiscoveryData;
  exp: number;
}

const DISCOVERY_CACHE = new Map<string, CacheEntry>();

async function discoverForIssuer(
  issuer: string,
  config: AuthConfig,
): Promise<DiscoveryData> {
  const http = getAxios(config);
  const cleanIssuer = issuer.replace(/\/+$/, "");
  const wellKnown = `${cleanIssuer}/.well-known/openid-configuration`;
  const { data } = await http.get(wellKnown);
  return {
    authorizationEndpoint: data.authorization_endpoint,
    tokenEndpoint: data.token_endpoint,
    jwksUri: data.jwks_uri,
    endSessionEndpoint: data.end_session_endpoint,
    issuer: data.issuer,
    userinfoEndpoint: data.userinfo_endpoint,
  };
}

/** Get (cached) OIDC discovery for a given issuer. Multi-issuer friendly. */
export async function getDiscoveryForIssuer(
  issuer: string,
  config: AuthConfig,
): Promise<DiscoveryData> {
  const cleanIssuer = issuer.replace(/\/+$/, "");
  const now = Date.now();
  const cached = DISCOVERY_CACHE.get(cleanIssuer);
  if (cached && now < cached.exp) return cached.data;

  const ttlMins = config.oidc?.discoveryTtlMinutes ?? 10;
  const ttlMs = ttlMins * 60 * 1000;

  const data = await discoverForIssuer(cleanIssuer, config);
  DISCOVERY_CACHE.set(cleanIssuer, { data, exp: now + ttlMs });
  return data;
}

/** Backward-compatible: discovery for the primary issuer in config. */
export async function getDiscovery(config: AuthConfig): Promise<DiscoveryData> {
  if (!config.oidc?.issuer)
    throw new Error("[auth-core] oidc.issuer is required");
  return getDiscoveryForIssuer(config.oidc.issuer, config);
}

// ── Open-redirect protection ────────────────────────────────────────────────

/** Strip any cross-origin component from a returnTo URL. Returns '/' on failure. */
export function sanitizeReturnTo(input: unknown): string {
  if (!input || typeof input !== "string") return "/";
  try {
    const u = new URL(input, "http://auth-core-local");
    if (u.origin !== "http://auth-core-local") return "/";
    return u.pathname + (u.search ?? "") + (u.hash ?? "");
  } catch {
    return "/";
  }
}
