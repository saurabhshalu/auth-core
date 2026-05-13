// src/utils/configResolver.ts

type Primitive = string | number | boolean | undefined;

const toBool = (v: Primitive, fallback = false): boolean => {
  if (v == null || v === "") return fallback;
  const s = String(v).trim().toLowerCase();
  if (["true", "1", "yes", "on"].includes(s)) return true;
  if (["false", "0", "no", "off"].includes(s)) return false;
  return fallback;
};

const toNum = (v: Primitive, fallback: number): number => {
  if (v == null || v === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};

const toJSON = <T>(v: Primitive, fallback: T): T => {
  if (!v) return fallback;
  try {
    return JSON.parse(String(v)) as T;
  } catch {
    return fallback;
  }
};

const toCSVorJSON = <T>(v: Primitive, fallback: T): T | string[] => {
  if (!v) return fallback;
  const trimmed = String(v).trim();
  if (trimmed.startsWith("[") || trimmed.startsWith("{"))
    return toJSON(trimmed, fallback);
  return trimmed
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
};

function pick<T>(
  a: T | undefined | null,
  b: T | undefined | null,
  fallback: T,
): T {
  return a ?? b ?? fallback;
}

// ── Public API ───────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function resolveConfig(
  userConfig: Record<string, any> = {},
): Record<string, any> {
  const u = userConfig;
  const c = (u["common"] as Record<string, any>) ?? {};
  const o = (u["oidc"] as Record<string, any>) ?? {};
  const cas = (u["cas"] as Record<string, any>) ?? {};
  const p = (u["proxy"] as Record<string, any>) ?? {};

  // Precedence: env (default) → ENV > CONFIG > DEFAULT
  //             config        → CONFIG > ENV > DEFAULT
  const disableEnv =
    (process.env["AUTH_CORE_DISABLE_ENV"] ?? "").toLowerCase() === "true";
  const priority = disableEnv
    ? "config"
    : (process.env["AUTH_CORE_ENV_PRIORITY"] ?? "env");
  const preferEnv = priority !== "config";

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const envFirst = (envVal: any, cfgVal: any, d: any) =>
    preferEnv ? pick(envVal, cfgVal, d) : pick(cfgVal, envVal, d);

  const common = {
    appBasePath: envFirst(
      process.env["AUTH_CORE_APP_BASE_PATH"],
      c["appBasePath"],
      "",
    ),
    authMode: String(
      envFirst(process.env["AUTH_CORE_AUTH_MODE"], c["authMode"], "OIDC"),
    ).toUpperCase(),
    sessionName: envFirst(
      process.env["AUTH_CORE_SESSION_NAME"],
      c["sessionName"],
      "NSESSIONID",
    ),
    sessionSecret: envFirst(
      process.env["AUTH_CORE_SESSION_SECRET"],
      c["sessionSecret"],
      undefined,
    ),
    environment: envFirst(
      process.env["AUTH_CORE_ENVIRONMENT"],
      c["environment"],
      process.env["NODE_ENV"] ?? "PRODUCTION",
    ),
    meEndpointContext: envFirst(
      process.env["AUTH_CORE_ME_ENDPOINT_CONTEXT"],
      c["meEndpointContext"],
      "/me",
    ),
    postLogoutRedirectUri: envFirst(
      process.env["AUTH_CORE_POST_LOGOUT_REDIRECT_URI"],
      c["postLogoutRedirectUri"],
      undefined,
    ),
    opId: envFirst(process.env["AUTH_CORE_OP_ID"], c["opId"], undefined),
    buId: envFirst(process.env["AUTH_CORE_BU_ID"], c["buId"], undefined),
    language: envFirst(
      process.env["AUTH_CORE_LANGUAGE"],
      c["language"],
      undefined,
    ),

    excludePathFromProtect: toCSVorJSON(
      preferEnv
        ? (process.env["AUTH_CORE_EXCLUDE_PATH_FROM_PROTECT"] ?? undefined)
        : undefined,
      c["excludePathFromProtect"] ?? [],
    ),
    sessionIdleTimeoutMins: toNum(
      preferEnv
        ? (process.env["AUTH_CORE_SESSION_IDLE_TIMEOUT_MINS"] ?? undefined)
        : undefined,
      c["sessionIdleTimeoutMins"] ?? 15,
    ),
    sessionCookieMode: String(
      envFirst(
        process.env["AUTH_CORE_SESSION_COOKIE_MODE"],
        c["sessionCookieMode"],
        "session",
      ),
    ).toLowerCase(),

    session: {
      store: c["session"]?.["store"],
      redis: {
        url: envFirst(
          process.env["AUTH_CORE_REDIS_URL"],
          c["session"]?.["redis"]?.["url"],
          undefined,
        ),
        prefix: envFirst(
          process.env["AUTH_CORE_REDIS_PREFIX"],
          c["session"]?.["redis"]?.["prefix"],
          undefined,
        ),
      },
    },
    allowMemoryStoreInProd: toBool(
      preferEnv
        ? (process.env["AUTH_CORE_ALLOW_MEMORY_STORE_IN_PROD"] ?? "")
        : "",
      false,
    ),
    tokenRefreshBufferMs: toNum(
      preferEnv
        ? (process.env["AUTH_CORE_TOKEN_REFRESH_BUFFER"] ?? undefined)
        : undefined,
      c["tokenRefreshBufferMs"] ?? 60 * 1000,
    ),
    reEnrichOnRefresh: preferEnv
      ? toBool(process.env["AUTH_CORE_RE_ENRICH_ON_REFRESH"], c["reEnrichOnRefresh"] ?? true)
      : (c["reEnrichOnRefresh"] ?? true),
    statelessHooks: preferEnv
      ? toBool(process.env["AUTH_CORE_STATELESS_HOOKS"], c["statelessHooks"] ?? true)
      : (c["statelessHooks"] ?? true),
    cookieSameSite: (envFirst(
      process.env["AUTH_CORE_COOKIE_SAME_SITE"],
      c["cookieSameSite"],
      "lax",
    ) as string).toLowerCase() as "lax" | "strict" | "none",
    healthEndpointContext: envFirst(
      process.env["AUTH_CORE_HEALTH_ENDPOINT_CONTEXT"],
      c["healthEndpointContext"],
      "/_health",
    ),
    disableHealthEndpoint: preferEnv
      ? toBool(process.env["AUTH_CORE_DISABLE_HEALTH_ENDPOINT"], c["disableHealthEndpoint"] ?? false)
      : (c["disableHealthEndpoint"] ?? false),
  };

  const oidc = {
    issuer: envFirst(
      process.env["AUTH_CORE_OIDC_ISSUER_URL"],
      o["issuer"],
      undefined,
    ),
    clientId: envFirst(
      process.env["AUTH_CORE_OIDC_CLIENT_ID"],
      o["clientId"],
      undefined,
    ),
    clientSecret: envFirst(
      process.env["AUTH_CORE_OIDC_CLIENT_SECRET"],
      o["clientSecret"],
      undefined,
    ),
    redirectUri: envFirst(
      process.env["AUTH_CORE_OIDC_REDIRECT_URI"],
      o["redirectUri"],
      undefined,
    ),
    scope: envFirst(
      process.env["AUTH_CORE_OIDC_SCOPE"],
      o["scope"],
      "openid profile email",
    ),
    enablePKCE: preferEnv
      ? toBool(
          process.env["AUTH_CORE_OIDC_ENABLE_PKCE"],
          o["enablePKCE"] ?? false,
        )
      : (o["enablePKCE"] ?? false),
    expectedAudience: envFirst(
      process.env["AUTH_CORE_OIDC_EXPECTED_AUDIENCE"],
      o["expectedAudience"],
      undefined,
    ),
    verifyAudience: preferEnv
      ? toBool(
          process.env["AUTH_CORE_VERIFY_AUDIENCE"],
          o["verifyAudience"] ?? false,
        )
      : (o["verifyAudience"] ?? false),
    includeLogoutClientId: preferEnv
      ? toBool(
          process.env["AUTH_CORE_OIDC_INCLUDE_LOGOUT_CLIENT_ID"],
          o["includeLogoutClientId"] ?? false,
        )
      : (o["includeLogoutClientId"] ?? false),

    codeChallengeMethod: o["codeChallengeMethod"] ?? "S256",
    discoveryTtlMinutes: toNum(
      preferEnv
        ? (process.env["AUTH_CORE_OIDC_DISCOVERY_TTL_MINUTES"] ?? undefined)
        : undefined,
      o["discoveryTtlMinutes"] ?? 10,
    ),
  };

  const casCfg = {
    servicePrefix: envFirst(
      process.env["AUTH_CORE_CAS_SERVICE_PREFIX"],
      cas["servicePrefix"],
      undefined,
    ),
    serverPath: envFirst(
      process.env["AUTH_CORE_CAS_SERVER_PATH"],
      cas["serverPath"],
      undefined,
    ),
    paths: preferEnv
      ? toJSON(process.env["AUTH_CORE_CAS_PATHS_OVERRIDE"], cas["paths"] ?? {})
      : (cas["paths"] ?? {}),
    overrideConfiguration: preferEnv
      ? toJSON(
          process.env["AUTH_CORE_CAS_OVERRIDE_CONFIGURATION"],
          cas["overrideConfiguration"] ?? {},
        )
      : (cas["overrideConfiguration"] ?? {}),
    ignore: cas["ignore"] ?? [],
    match: cas["match"] ?? [],
    slo: cas["slo"] !== false,
    tokenSecret: envFirst(
      process.env["AUTH_CORE_CAS_TOKEN_SECRET"],
      u["casTokenSecret"] ?? cas["tokenSecret"],
      undefined,
    ),
    tokenExpiresIn: toNum(
      preferEnv
        ? (process.env["AUTH_CORE_CAS_TOKEN_EXPIRES_IN_SECONDS"] ?? undefined)
        : undefined,
      cas["tokenExpiresIn"] ?? 3600,
    ),
  };

  const proxy = {
    enabled: preferEnv
      ? toBool(process.env["AUTH_CORE_PROXY_ENABLED"], p["enabled"] ?? false)
      : (p["enabled"] ?? false),
    protocol: envFirst(
      process.env["AUTH_CORE_PROXY_PROTOCOL"],
      p["protocol"],
      "http",
    ),
    host: envFirst(process.env["AUTH_CORE_PROXY_HOST"], p["host"], undefined),
    port: envFirst(process.env["AUTH_CORE_PROXY_PORT"], p["port"], undefined),
    auth:
      process.env["AUTH_CORE_PROXY_USERNAME"] ||
      process.env["AUTH_CORE_PROXY_PASSWORD"]
        ? {
            username: process.env["AUTH_CORE_PROXY_USERNAME"],
            password: process.env["AUTH_CORE_PROXY_PASSWORD"],
          }
        : p["auth"],
    noProxy: preferEnv
      ? toCSVorJSON(process.env["AUTH_CORE_NO_PROXY"], p["noProxy"] ?? [])
      : (p["noProxy"] ?? []),
  };

  return { ...u, common, oidc, cas: casCfg, proxy };
}

/** Fail-fast validation. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function validateConfig(cfg: Record<string, any>): true {
  const envU = String(cfg["common"]?.["environment"] ?? "").toUpperCase();
  const mode = String(cfg["common"]?.["authMode"] ?? "OIDC").toUpperCase();
  const isDev = envU === "DEVELOPMENT";

  const cookieMode = cfg["common"]?.["sessionCookieMode"];
  if (!["session", "persistent"].includes(cookieMode)) {
    throw new Error(
      `[auth-core] Invalid common.sessionCookieMode: "${cookieMode}". Use "session" or "persistent".`,
    );
  }

  if (!isDev && !cfg["common"]?.["sessionSecret"]) {
    throw new Error(
      "[auth-core] common.sessionSecret is required in non-development environments.",
    );
  }

  const hasProvidedStore = !!cfg["common"]?.["session"]?.["store"];
  const autoRedisUrl =
    process.env["AUTH_CORE_REDIS_URL"] ??
    cfg["common"]?.["session"]?.["redis"]?.["url"];
  const willUseMemoryStore = !hasProvidedStore && !autoRedisUrl;

  if (
    !isDev &&
    willUseMemoryStore &&
    !cfg["common"]?.["allowMemoryStoreInProd"]
  ) {
    throw new Error(
      "[auth-core] MemoryStore not allowed in non-development. " +
        "Provide a persistent session store or set AUTH_CORE_ALLOW_MEMORY_STORE_IN_PROD=true.",
    );
  }

  if (mode === "OIDC") {
    if (!cfg["oidc"]?.["issuer"])
      throw new Error("[auth-core] OIDC: issuer is required.");
    if (!cfg["oidc"]?.["clientId"])
      throw new Error("[auth-core] OIDC: clientId is required.");
    if (!cfg["oidc"]?.["redirectUri"])
      throw new Error("[auth-core] OIDC: redirectUri is required.");
    if (
      cfg["oidc"]?.["verifyAudience"] &&
      !(cfg["oidc"]?.["expectedAudience"] || cfg["oidc"]?.["clientId"])
    ) {
      throw new Error(
        "[auth-core] OIDC: verifyAudience=true but no expectedAudience or clientId available.",
      );
    }
  } else if (mode === "CAS") {
    if (!cfg["cas"]?.["servicePrefix"])
      throw new Error("[auth-core] CAS: servicePrefix is required.");
    if (!cfg["cas"]?.["serverPath"])
      throw new Error("[auth-core] CAS: serverPath is required.");
  } else if (mode === "NONE") {
    // no-op
  } else {
    throw new Error(
      `[auth-core] Unsupported authMode: ${cfg["common"]?.["authMode"]}`,
    );
  }

  if (cfg["proxy"]?.["enabled"]) {
    if (!cfg["proxy"]?.["host"] || !cfg["proxy"]?.["port"]) {
      throw new Error(
        "[auth-core] proxy.enabled=true but proxy.host or proxy.port is missing.",
      );
    }
  }

  return true;
}
