// src/types.ts
// Central TypeScript interfaces for auth-core.
// All modules import from here — no inline type definitions.

import type { Store } from "express-session";

// ── Proxy ──────────────────────────────────────────────────────────────────

export interface ProxyAuth {
  username: string;
  password?: string;
}

export interface ProxyConfig {
  enabled?: boolean;
  protocol?: "http" | "https";
  host?: string;
  port?: string | number;
  auth?: ProxyAuth;
  noProxy?: string | string[];
}

// ── Session ────────────────────────────────────────────────────────────────

export interface RedisSessionOptions {
  url?: string;
  prefix?: string;
}

export interface SessionConfig {
  store?: Store;
  redis?: RedisSessionOptions;
}

// ── Common ─────────────────────────────────────────────────────────────────

export interface CommonConfig {
  appBasePath?: string;
  authMode?: "OIDC" | "CAS" | "NONE";
  sessionName?: string;
  sessionSecret?: string;
  environment?: string;
  meEndpointContext?: string;
  healthEndpointContext?: string;
  disableHealthEndpoint?: boolean;
  postLogoutRedirectUri?: string;
  opId?: string;
  buId?: string;
  language?: string;
  excludePathFromProtect?: string[];
  sessionIdleTimeoutMins?: number;
  sessionCookieMode?: "session" | "persistent";
  session?: SessionConfig;
  allowMemoryStoreInProd?: boolean;
  pathClientMappingList?: PathClientMapping[];
  tokenRefreshBufferMs?: number;
  cookieSameSite?: "lax" | "strict" | "none";
  reEnrichOnRefresh?: boolean;
  statelessHooks?: boolean;
}

// ── OIDC ───────────────────────────────────────────────────────────────────

export interface OidcConfig {
  issuer?: string;
  clientId?: string;
  clientSecret?: string | null;
  redirectUri?: string;
  scope?: string;
  algorithm?: string;
  verifyAudience?: boolean;
  expectedAudience?: string;
  includeLogoutClientId?: boolean;
  enablePKCE?: boolean;
  codeChallengeMethod?: "S256" | "plain";
  discoveryTtlMinutes?: number;
}

/** Shape accepted in pathClientMappingList items — snake_case aliases for backward compat */
export interface PathClientMappingOidc extends Partial<OidcConfig> {
  client_id?: string;
  client_secret?: string;
  redirect_uri?: string;
  expected_audience?: string;
}

export interface PathClientMapping {
  paths: string[];
  oidc?: PathClientMappingOidc;
  clientKey?: string;
  name?: string;
}

/** A fully-resolved, normalized OIDC config (all fields definite after mergeOidc). */
export interface ResolvedOidc {
  issuer: string;
  clientId: string;
  clientSecret?: string | null;
  redirectUri: string;
  scope: string;
  algorithm: string;
  verifyAudience?: boolean;
  expectedAudience: string;
  includeLogoutClientId: boolean;
  enablePKCE: boolean;
  codeChallengeMethod: "S256" | "plain";
}

// ── CAS ────────────────────────────────────────────────────────────────────

export interface CasPathsConfig {
  login?: string;
  logout?: string;
  validate?: string;
  serviceValidate?: string;
  proxy?: string | false;
  proxyCallback?: string | false;
}

export interface CasConfig {
  servicePrefix?: string;
  serverPath?: string;
  paths?: CasPathsConfig;
  ignore?: string[];
  match?: string[];
  slo?: boolean;
  overrideConfiguration?: Record<string, unknown>;
  tokenSecret?: string;
  tokenExpiresIn?: number;
}

// ── Hooks ──────────────────────────────────────────────────────────────────

import type { Request } from "express";

export interface BeforeAuthRedirectResult {
  persistIntent?: string;
  extraAuthParams?: Record<string, string>;
}

export interface AfterTokensVerifiedResult {
  userPatch?: Record<string, unknown>;
  redirectTo?: string;
}

export interface BeforeAuthRedirectArgs {
  req: Request;
  providerKey: string;
  provider: ResolvedOidc;
  intent?: string | null;
}

export interface AfterTokensVerifiedArgs {
  req: Request;
  providerKey: string;
  provider: ResolvedOidc;
  tokens: TokenSet;
  idPayload: JwtPayload;
  accessPayload: JwtPayload;
  intent?: string | null;
}

export interface AuthHooks {
  beforeAuthRedirect?: (
    args: BeforeAuthRedirectArgs,
  ) => Promise<BeforeAuthRedirectResult | void | null | undefined>;
  afterTokensVerified?: (
    args: AfterTokensVerifiedArgs,
  ) => Promise<AfterTokensVerifiedResult | void | null | undefined>;
}

// ── Logger ─────────────────────────────────────────────────────────────────

export interface Logger {
  debug?: (...args: unknown[]) => void;
  info?: (...args: unknown[]) => void;
  warn?: (...args: unknown[]) => void;
  error?: (...args: unknown[]) => void;
  log?: (...args: unknown[]) => void;
}

// ── Token ───────────────────────────────────────────────────────────────────

export interface TokenSet {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
}

// ── JWT Payload ─────────────────────────────────────────────────────────────

export interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nonce?: string;
  preferred_username?: string;
  email?: string;
  given_name?: string;
  family_name?: string;
  roles?: string[];
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
  organization?: Record<
    string,
    {
      opId?: string[];
      buId?: string[];
      language?: string[];
      [k: string]: unknown;
    }
  >;
  opId?: string;
  buId?: string;
  language?: string;
  events?: Record<string, unknown>;
  sid?: string;
  [key: string]: unknown;
}

// ── User ────────────────────────────────────────────────────────────────────

export interface AuthUser {
  username: string;
  firstName?: string;
  lastName?: string;
  email?: string | null;
  roles: string[];
  organization?: string;
  opId?: string;
  buId?: string;
  language?: string;

  raw?: JwtPayload;
  [key: string]: unknown; // allow enrichment fields
}

// ── Pending Auth ─────────────────────────────────────────────────────────────

export interface PendingOidc {
  issuer: string;
  clientId: string;
  clientSecret?: string | null;
  expectedAudience: string;
  redirectUri: string;
  includeLogoutClientId: boolean;
  algorithm: string;
}

export interface PendingAuth {
  state: string;
  nonce: string;
  returnTo: string;
  intent?: string | null;
  pkceVerifier?: string | null;
  createdAt: number;
  clientKey: string;
  oidc: PendingOidc;
}

// ── Session Augmentation ────────────────────────────────────────────────────

declare module "express-session" {
  interface SessionData {
    user?: AuthUser;
    tokens?: TokenSet;
    activeOidc?: Partial<ResolvedOidc> & { clientKey?: string };
    pending?: PendingAuth;
    cas?: { user: string; [key: string]: unknown };
    _enriched?: boolean;
    lastReturnTo?: string;
  }
}

// ── Full Config ─────────────────────────────────────────────────────────────

import type { SessionData } from "express-session";

export interface AuthConfig {
  common?: CommonConfig;
  oidc?: OidcConfig;
  cas?: CasConfig;
  proxy?: ProxyConfig;
  hooks?: AuthHooks;
  logger?: Logger;
  enrichMe?: (session: SessionData) => Promise<Record<string, unknown>>;
  enrichSession?: (session: SessionData) => Promise<void>;
  casTokenSecret?: string;
}

// ── OTel options ────────────────────────────────────────────────────────────

export interface OtelOptions {
  serviceName?: string;
  serviceVersion?: string;
  environment?: string;
  endpoint?: string;
  headers?: Record<string, string>;
  enableMetrics?: boolean;
  enableTraces?: boolean;
  metricsIntervalMs?: number;
  instrumentations?: Record<string, object>;
  logLevel?: "none" | "error" | "warn" | "info" | "debug";
}

export interface OtelHandle {
  shutdown: () => Promise<void>;
}
