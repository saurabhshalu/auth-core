# @saurabhshalu/auth-core

**Central Authentication for Node.js (Express) apps** with **OIDC** and **CAS**, secure sessions, auto‑Redis, proxy + `NO_PROXY` support, OpenTelemetry bootstrap, structured logging, and a simple `/me` endpoint—now in **Pure TypeScript**.

---

## ✨ Features

- 🛡️ **Pure TypeScript**: Fully typed with first-class support for ESM and CommonJS.
- ✅ **Auth modes**: `OIDC`, `CAS`, or `NONE`
- ✅ **Stateless Support**: Cookieless Bearer token validation for APIs.
- ✅ **One‑liner setup**: `setupAuth(app, config)` + `protect(config)`
- ✅ **/me endpoint** with optional enrichment hooks
- ✅ **Session management**:
  - `session` or `persistent` cookie modes
  - Auto‑enable **Redis** via env for multi‑pod deployments
  - Guard against MemoryStore in production
- ✅ **OIDC Niceties**: PKCE (dynamic hashing), audience verification, token refresh
- ✅ **CAS** integration with custom path support and JWT-synthetic tokens
- ✅ **Proxy** support with **`NO_PROXY`/`no_proxy`** bypass
- ✅ **OpenTelemetry** bootstrap (traces & metrics) with side-effect safety
- ✅ **Structured logging** adapter + per‑request logger middleware
- ✅ **ENV overrides** for all scalar settings with 12-factor compliance

---

## ⚙️ Requirements

- **Node.js**: v18+ (v20+ recommended)
- **Express**: v4+ or v5
- **TypeScript**: v5+ (for consuming types)

---

## 📦 Installation

```bash
npm install @saurabhshalu/auth-core
```

---

## 🚀 Quick Start (OIDC)

### 1. Initialize Auth

**app.ts** (or app.js)

```typescript
import express from "express";
import { setupAuth, protect } from "@saurabhshalu/auth-core";
import { authConfig } from "./authConfig.js";

const app = express();

// 1) Setup auth (registers session & routes like /callback, /logout, /me)
setupAuth(app, authConfig);

// 2) Protect your routes (Session-based for UI, Bearer-based for APIs)
app.use(protect(authConfig));

// 3) Your app routes
app.get("/api/data", (req, res) => {
  // req.user is now populated
  res.json({ data: "Top Secret", user: req.user });
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

### 2. Configuration

**authConfig.ts**

```typescript
import type { AuthConfig } from "@saurabhshalu/auth-core/types";

export const authConfig: AuthConfig = {
  common: {
    appBasePath: "/my-app",
    authMode: "OIDC",
    environment: "PRODUCTION",
    sessionSecret: process.env.AUTH_CORE_SESSION_SECRET, // Required in PROD
    sessionCookieMode: "session", // "session" (on close) or "persistent"
    postLogoutRedirectUri: "https://myapp.com/my-app",
  },
  oidc: {
    issuer: "https://auth.example.com/realms/myrealm",
    clientId: "my-client-id",
    redirectUri: "https://myapp.com/my-app/callback",
    enablePKCE: true,
    scope: "openid profile email organization",
    verifyAudience: true,
  },
  // 3. Enrichment Hooks (Optional)
  enrichMe: async (session) => {
    // Add extra data to the /me response (e.g., from an external DB)
    return { 
      permissions: ["READ_ONLY"],
      lastLogin: new Date().toISOString() 
    };
  },
  enrichSession: async (session) => {
    // Modify the session object once immediately after authentication
    session.customSessionFlag = "verified";
  },
  // 4. Lifecycle Hooks (Optional)
  hooks: {
    beforeAuthRedirect: async ({ req, provider }) => {
      // Add extra query params to the OIDC login URL
      return { 
        extraAuthParams: { ui_locales: "en-GB" },
        persistIntent: req.query.intent as string 
      };
    },
    afterTokensVerified: async ({ tokens, userPatch }) => {
      // Patch the user object based on token claims
      return {
        userPatch: { isAdmin: tokens.access_token.includes("admin_role") }
      };
    }
  }
};
```

---

## 🌍 Stateless Bearer Support

If a request contains an `Authorization: Bearer <token>` header, the library automatically:

1. **Skips the session middleware** (no cookies set, no Redis lookups).
2. **Validates the token** against the OIDC provider.
3. **Attaches the user** to `req.user` and `req.auth`.

This allows your application to serve both web users (session-based) and mobile/API clients (stateless) using the same route protection.

---

## 📈 OpenTelemetry Bootstrap

Initialize tracing and metrics at the very top of your entry point:

```typescript
import otel from "@saurabhshalu/auth-core/otel";

// Initialize with defaults (uses OTEL_* env variables)
otel({
  serviceName: "My-Service",
  logLevel: "info",
});
```

---

## 🧭 Structured Logging

The library includes a Winston/Pino-compatible adapter that automatically redacts sensitive tokens and headers.

```typescript
import { requestLogger } from "@saurabhshalu/auth-core/utils/logger";

// Register the request logger to get `req.log` and `req.requestId`
app.use(requestLogger(myWinstonInstance));

app.get("/test", (req, res) => {
  req.log.info("Processing test request"); // Includes requestId automatically
  res.send("OK");
});
```

---

## ⚓ Enrichment Hooks

Fine-tune your user data without modifying the core library.

### `enrichMe`
Allows you to add extra fields to the JSON returned by the `/me` endpoint. Useful for merging profile data from your own database.
```typescript
enrichMe: async (session) => ({
  companyName: "Acme Corp"
})
```

### `enrichSession`
A one-time hook executed immediately after successful login. Use this to attach custom flags or data to `req.session` that should persist throughout the user's visit.
```typescript
enrichSession: async (session) => {
  session.isVip = true;
}
```

---

## 🪝 Lifecycle Hooks

Intercept and modify the authentication flow at key points.

### `beforeAuthRedirect`
Runs right before the user is redirected to the OIDC provider. Use this to pass extra OIDC parameters (like `prompt`, `login_hint`, or `ui_locales`).
```typescript
beforeAuthRedirect: async ({ req }) => ({
  extraAuthParams: { login_hint: req.query.email }
})
```

### `afterTokensVerified`
Runs after OIDC tokens are successfully verified (works for both **initial login** and **token refresh**). Use this to perform final user object patches or determine a custom redirect path.
```typescript
afterTokensVerified: async ({ tokens }) => {
  // Logic based on tokens.id_token or tokens.access_token
  return {
    userPatch: { lastLogin: Date.now() }
  };
}
```

---

## ⚙️ Environment Variables Reference

All scalar configuration fields can be overridden using environment variables. By default, **Environment Variables take precedence** over the `authConfig` object (12-Factor style).

### 1. General & Session

| Variable                               | Description                        | Default      | Options                     |
| :------------------------------------- | :--------------------------------- | :----------- | :-------------------------- |
| `AUTH_CORE_AUTH_MODE`                  | Authentication protocol            | `OIDC`       | `OIDC`, `CAS`, `NONE`       |
| `AUTH_CORE_ENVIRONMENT`                | App environment                    | `PRODUCTION` | `DEVELOPMENT`, `PRODUCTION` |
| `AUTH_CORE_SESSION_SECRET`             | Secret for signing session cookies | `undefined`  | **Required in PRODUCTION**  |
| `AUTH_CORE_APP_BASE_PATH`              | Base path for all auth routes      | `""`         | e.g. `/my-app`              |
| `AUTH_CORE_ME_ENDPOINT_CONTEXT`        | Path for the `/me` user API        | `/me`        | e.g. `/api/profile`         |
| `AUTH_CORE_SESSION_NAME`               | Name of the session cookie         | `NSESSIONID` |                             |
| `AUTH_CORE_SESSION_COOKIE_MODE`        | Cookie persistence                 | `session`    | `session`, `persistent`     |
| `AUTH_CORE_SESSION_IDLE_TIMEOUT_MINS`  | Max age for persistent cookies     | `15`         | minutes                     |
| `AUTH_CORE_COOKIE_SAME_SITE`           | Cookie SameSite attribute          | `lax`        | `lax`, `strict`, `none`     |
| `AUTH_CORE_ALLOW_MEMORY_STORE_IN_PROD` | Allow MemoryStore in PRODUCTION    | `false`      | `true` (NOT recommended)    |
| `AUTH_CORE_TOKEN_REFRESH_BUFFER`       | Buffer for auto-refresh (ms)       | `60000`      | 60 seconds                  |
| `AUTH_CORE_ENV_PRIORITY`               | Precedence for resolution          | `env`        | `env` (ENV first), `config` |

### 2. OIDC (OpenID Connect)

| Variable                               | Description                        | Default                | Options                |
| :------------------------------------- | :--------------------------------- | :--------------------- | :--------------------- |
| `AUTH_CORE_OIDC_ISSUER_URL`            | Base URL of the OIDC provider      | `undefined`            | **Required**           |
| `AUTH_CORE_OIDC_CLIENT_ID`             | OIDC Client ID                     | `undefined`            | **Required**           |
| `AUTH_CORE_OIDC_CLIENT_SECRET`         | OIDC Client Secret                 | `undefined`            | Optional               |
| `AUTH_CORE_OIDC_REDIRECT_URI`          | Full callback URL                  | `undefined`            | **Required**           |
| `AUTH_CORE_OIDC_SCOPE`                 | Scopes to request                  | `openid profile email` | space-separated string |
| `AUTH_CORE_OIDC_ENABLE_PKCE`           | Enable Proof Key for Code Exchange | `true`                 | `true`, `false`        |
| `AUTH_CORE_VERIFY_AUDIENCE`            | Verify `aud` claim in tokens       | `false`                | `true`, `false`        |
| `AUTH_CORE_OIDC_EXPECTED_AUDIENCE`     | Expected audience if not clientId  | `undefined`            |                        |
| `AUTH_CORE_OIDC_DISCOVERY_TTL_MINUTES` | Discovery cache TTL (mins)         | `10`                   | Default 10 minutes     |

### 3. Redis & Auto-Store

| Variable                      | Description                     | Default     | Options                        |
| :---------------------------- | :------------------------------ | :---------- | :----------------------------- |
| `AUTH_CORE_SESSION_STORE`     | Enable automatic Redis store    | `undefined` | Set to `redis` to enable       |
| `AUTH_CORE_REDIS_URL`         | Redis connection string         | `undefined` | e.g. `redis://localhost:6379`  |
| `AUTH_CORE_REDIS_PREFIX`      | Prefix for session keys         | `sess:`     |                                |
| `AUTH_CORE_SESSION_INIT_MODE` | Error behavior if Redis is down | `fail`      | `fail`, `fallback` (to Memory) |

### 4. CAS (Central Authentication Service)

| Variable                                 | Description                     | Default     | Options              |
| :--------------------------------------- | :------------------------------ | :---------- | :------------------- |
| `AUTH_CORE_CAS_SERVER_PATH`              | Base URL of the CAS server      | `undefined` | **Required for CAS** |
| `AUTH_CORE_CAS_SERVICE_PREFIX`           | External URL of your app        | `undefined` | **Required for CAS** |
| `AUTH_CORE_CAS_TOKEN_SECRET`             | Secret for synthetic CAS tokens | `undefined` | **Required for CAS** |
| `AUTH_CORE_CAS_TOKEN_EXPIRES_IN_SECONDS` | Synthetic token TTL             | `3600`      |                      |

### 5. OpenTelemetry (Monitoring)

| Variable                      | Description                    | Default                    |
| :---------------------------- | :----------------------------- | :------------------------- |
| `OTEL_SERVICE_NAME`           | Service name in traces/metrics | Auto-inferred              |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint        | `http://localhost:4318`    |
| `OTEL_EXPORTER_OTLP_HEADERS`  | Collector auth headers         | `Authorization=Bearer ...` |
| `OTEL_ENABLE_TRACES`          | Enable span collection         | `true`                     |
| `OTEL_ENABLE_METRICS`         | Enable metric collection       | `true`                     |

### 6. Corporate Proxy

| Variable                  | Description                        | Default               |
| :------------------------ | :--------------------------------- | :-------------------- |
| `AUTH_CORE_PROXY_ENABLED` | Use an outbound proxy for OIDC/CAS | `false`               |
| `AUTH_CORE_PROXY_HOST`    | Proxy hostname                     | `undefined`           |
| `AUTH_CORE_PROXY_PORT`    | Proxy port                         | `undefined`           |
| `AUTH_CORE_NO_PROXY`      | Bypass proxy for these hosts       | `localhost,127.0.0.1` |

---

## 📄 License

MIT © Saurabh Verma
