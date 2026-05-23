# Enterprise Node.js Authentication for Express (OIDC, CAS, Redis, OpenTelemetry)

[![npm version](https://img.shields.io/npm/v/@saurabhshalu/auth-core.svg?style=flat-square)](https://www.npmjs.com/package/@saurabhshalu/auth-core)
[![npm downloads](https://img.shields.io/npm/dm/@saurabhshalu/auth-core.svg?style=flat-square)](https://www.npmjs.com/package/@saurabhshalu/auth-core)
[![license](https://img.shields.io/npm/l/@saurabhshalu/auth-core.svg?style=flat-square)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)

An enterprise-grade, highly resilient **Node.js authentication** library for **Express authentication** built in **Pure TypeScript**. Out-of-the-box support for **OIDC authentication** (**OpenID Connect**) and **CAS authentication**, secure sessions, automated multi-pod **Redis session store** failover, outbound enterprise proxy support, and native **OpenTelemetry tracing** & metrics bootstrap.

---

## 💡 Why auth-core?

Standard **Express authentication** libraries often require hundreds of lines of complex boilerplate, custom session store handlers, manual token refreshes, and insecure session defaults. `auth-core` provides a resilient, secure solution out of the box:

* 🔑 **One-Liner Integration**: Complete authentication setup in just two functions (`setupAuth` + `protect`).
* 📊 **Production-Grade Resiliency**: Automated **Redis session store** management with automated connection retries, health guards, and secure local in-memory fallbacks.
* 📈 **Built-in Observability**: Native **OpenTelemetry tracing** and structured logging with automatic sensitive token/header redaction.
* 🛡️ **Unified Auth Protocol**: Handle stateful sessions alongside cookieless **bearer token authentication** for APIs under a single protection schema.

---

## 📐 Architecture Flow

The library cleanly intercepts incoming request context to validate sessions or bearer tokens, seamlessly managing redirects and session storage:

```
  [ Client / Browser ]          [ Express App ]          [ auth-core ]          [ Identity Provider ]
          │                            │                       │                          │
          │────── 1. Request ─────────>│                       │                          │
          │                            │── 2. Check Session ──>│                          │
          │                            │                       │─── 3. Auth Redirect ────>│
          │<──────── 4. Login Redirect ────────────────────────│                          │
          │                            │                       │                          │
          │───────────── 5. Authenticate & Callback ─────────────────────────────────────>│
          │<──────────── 6. Code / Token Exchange ────────────────────────────────────────│
          │                            │                       │                          │
          │                            │<── 7. Save Session ───│                          │
          │                            │                       │                          │
          │<───── 8. Authenticated ────│                       │                          │
```

---

## 📦 Installation

```bash
npm install @saurabhshalu/auth-core
```

---

## ⚡ Quick Start

Get up and running with a secure **OIDC authentication** setup in less than 20 lines of code:

```typescript
import express from "express";
import { setupAuth, protect } from "@saurabhshalu/auth-core";

const app = express();

// 1. Define the authentication configuration
const authConfig = {
  common: { authMode: "OIDC", sessionSecret: "my-secure-session-secret" },
  oidc: {
    issuer: "https://auth.example.com/realms/myrealm",
    clientId: "my-app-client",
    redirectUri: "http://localhost:3000/callback",
  }
};

// 2. Initialize authentication & mount core callback routes
setupAuth(app, authConfig);

// 3. Protect routes with the configuration
app.get("/dashboard", protect(authConfig), (req, res) => {
  res.json({ message: "Hello secure world!", user: req.user });
});

app.listen(3000, () => console.log("Server listening on port 3000"));
```

---

## 🚀 Advanced Setup (Full Configuration)

For production systems requiring session enrichment, lifecycle hooks, and fine-grained control:

```typescript
import type { AuthConfig } from "@saurabhshalu/auth-core/types";

export const authConfig: AuthConfig = {
  common: {
    appBasePath: "/my-app",
    authMode: "OIDC",
    environment: "PRODUCTION",
    sessionSecret: process.env.AUTH_CORE_SESSION_SECRET,
    sessionCookieMode: "session",
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
  enrichMe: async (session) => ({ 
    permissions: ["READ_ONLY"],
    lastLogin: new Date().toISOString() 
  }),
  enrichSession: async (session) => {
    session.customSessionFlag = "verified";
  },
  hooks: {
    beforeAuthRedirect: async ({ req }) => ({ 
      extraAuthParams: { ui_locales: "en-GB" },
      persistIntent: req.query.intent as string 
    }),
    afterTokensVerified: async ({ tokens }) => ({
      userPatch: { isAdmin: tokens.access_token.includes("admin_role") }
    })
  }
};
```

---

## 🌍 Stateless Bearer Support

If a request contains an `Authorization: Bearer <token>` header, the library automatically bypasses stateful session management. It validates the signature against the active **OpenID Connect** provider and populates `req.user` and `req.auth`.

This allows your application to seamlessly support traditional web UI users (session-based) alongside mobile apps and service-to-service clients (**bearer token authentication**) using the exact same route decorators.

---

## 📈 OpenTelemetry & Custom Tracing

Initialize tracing at the absolute entry point of your server (before importing express or any database drivers):

```typescript
import otel from "@saurabhshalu/auth-core/otel";

otel({
  serviceName: "My-Service",
  logLevel: "info",
});
```

### Trace Enrichment Helper

Enrich the active trace from anywhere in your application (e.g. inside Express handlers or background jobs):

```typescript
import { trace } from "@saurabhshalu/auth-core/otel";

app.post("/api/checkout", (req, res) => {
  // Attach attributes to the active span safely (null/undefined values are ignored)
  trace.setAttributes({
    "business.service_type": "checkout",
    "business.tenant_id": req.body.tenantId,
  });

  // Add custom events
  trace.addEvent("payment_initiated");

  res.json({ success: true });
});
```

> [!TIP]
> Avoid using high-cardinality values (e.g. raw request payloads, UUIDs, or dynamic database IDs) as **attribute keys** to prevent telemetry storage bloat and performance degradation. Use clean namespaces like `business.*`.

---

## 🧭 Structured Logging

Includes a Winston/Pino-compatible logging adapter that automatically intercepts and redacts sensitive application headers and payload secrets:

```typescript
import { requestLogger } from "@saurabhshalu/auth-core/utils/logger";

// Mount the structured request logger
app.use(requestLogger(myWinstonInstance));

app.get("/test", (req, res) => {
  req.log.info("Processing test request"); // Automatically carries request context IDs
  res.send("OK");
});
```

---

## ⚙️ Environment Variables Reference

All configurations can be overridden using system environment variables, following 12-factor application design principles. **Environment Variables take precedence** over configuration objects by default.

### ⚡ Quick ENV Example

```bash
AUTH_CORE_AUTH_MODE=OIDC \
AUTH_CORE_SESSION_SECRET=super-secret-key-123 \
AUTH_CORE_OIDC_ISSUER_URL=https://auth.example.com/realms/myrealm \
AUTH_CORE_OIDC_CLIENT_ID=my-client-id \
AUTH_CORE_OIDC_REDIRECT_URI=https://myapp.com/callback \
AUTH_CORE_SESSION_STORE=redis \
AUTH_CORE_REDIS_URL=redis://localhost:6379 \
node app.js
```

### 1. General & Session

| Variable | Description | Default | Options |
| :--- | :--- | :--- | :--- |
| `AUTH_CORE_AUTH_MODE` | Authentication protocol | `OIDC` | `OIDC`, `CAS`, `NONE` |
| `AUTH_CORE_ENVIRONMENT` | App environment | `PRODUCTION` | `DEVELOPMENT`, `PRODUCTION` |
| `AUTH_CORE_SESSION_SECRET` | Secret for signing session cookies | `undefined` | **Required in PRODUCTION** |
| `AUTH_CORE_APP_BASE_PATH` | Base path for all auth routes | `""` | e.g. `/my-app` |
| `AUTH_CORE_ME_ENDPOINT_CONTEXT` | Path for the `/me` user API | `/me` | e.g. `/api/profile` |
| `AUTH_CORE_SESSION_NAME` | Name of the session cookie | `NSESSIONID` | |
| `AUTH_CORE_SESSION_COOKIE_MODE` | Cookie persistence | `session` | `session`, `persistent` |
| `AUTH_CORE_ALLOW_MEMORY_STORE_IN_PROD` | Allow MemoryStore in PRODUCTION | `false` | `true` (NOT recommended) |
| `AUTH_CORE_HEALTH_ENDPOINT_CONTEXT` | Path for the health endpoint | `/_health` | e.g. `/healthz` |
| `AUTH_CORE_DISABLE_HEALTH_ENDPOINT` | Disable the built-in health route | `false` | `true`, `false` |

### 2. OIDC (OpenID Connect)

| Variable | Description | Default | Options |
| :--- | :--- | :--- | :--- |
| `AUTH_CORE_OIDC_ISSUER_URL` | Base URL of the OIDC provider | `undefined` | **Required** |
| `AUTH_CORE_OIDC_CLIENT_ID` | OIDC Client ID | `undefined` | **Required** |
| `AUTH_CORE_OIDC_CLIENT_SECRET` | OIDC Client Secret | `undefined` | Optional |
| `AUTH_CORE_OIDC_REDIRECT_URI` | Full callback URL | `undefined` | **Required** |
| `AUTH_CORE_OIDC_SCOPE` | Scopes to request | `openid profile email` | space-separated string |
| `AUTH_CORE_OIDC_ENABLE_PKCE` | Enable Proof Key for Code Exchange | `false` | `true`, `false` |

### 3. Redis & Auto-Store

| Variable | Description | Default | Options |
| :--- | :--- | :--- | :--- |
| `AUTH_CORE_SESSION_STORE` | Enable automatic Redis store | `undefined` | Set to `redis` to enable |
| `AUTH_CORE_REDIS_URL` | Redis connection string | `undefined` | e.g. `redis://localhost:6379` |
| `AUTH_CORE_REDIS_PREFIX` | Prefix for session keys | `sess:` | |
| `AUTH_CORE_SESSION_INIT_MODE` | Error behavior if Redis is down | `fail` | `fail`, `fallback` (to Memory) |

#### 🛡️ Redis & Auto-Store Resiliency Behavior

Under network partitions, database outages, or dynamic node crashes, the initialization behavior is controlled by the `AUTH_CORE_SESSION_INIT_MODE` parameter:

*   **Fail Mode (`fail`)**: Instantly aborts the bootstrapping process and throws a hard startup exception if the remote Redis instance is unreachable. This prevents split-brain session states or data loss in strict, highly stateful environments.
*   **Fallback Mode (`fallback`)**: Seamlessly shunts active sessions and incoming request state into an encrypted, local in-memory store. Simultaneously, it spawns an async exponential backoff retry handler (5 attempts, max delay 10 seconds). Once the remote database heartbeat health check resolves, sessions are transparently re-synchronized without dropping client connections or requiring application restarts.

### 4. CAS (Central Authentication Service)

| Variable | Description | Default | Options |
| :--- | :--- | :--- | :--- |
| `AUTH_CORE_CAS_SERVER_PATH` | Base URL of the CAS server | `undefined` | **Required for CAS** |
| `AUTH_CORE_CAS_SERVICE_PREFIX` | External URL of your app | `undefined` | **Required for CAS** |
| `AUTH_CORE_CAS_TOKEN_SECRET` | Secret for synthetic CAS tokens | `undefined` | **Required for CAS** |

### 5. OpenTelemetry (Monitoring)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `OTEL_SERVICE_NAME` | Service name in traces/metrics | Auto-inferred |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | `http://localhost:4318` |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attrs (key=val,...) | `""` |
| `OTEL_ENABLE_TRACES` | Enable span collection | `true` |

### 6. Corporate Proxy

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AUTH_CORE_PROXY_ENABLED` | Use an outbound proxy for OIDC/CAS | `false` |
| `AUTH_CORE_PROXY_HOST` | Proxy hostname | `undefined` |
| `AUTH_CORE_NO_PROXY` | Bypass proxy for these hosts | `localhost,127.0.0.1` |

---

## ❓ FAQ / Troubleshooting

### 🔑 Token Expiry & Silent Rotation
**Q: How does the library handle expired access tokens?**  
**A:** `auth-core` applies an automated silent rotation mechanism during route protection. If an OIDC access token is nearing expiry (within the configured `tokenRefreshBufferMs` leeway), it leverages the stored `refresh_token` to retrieve a fresh token set from the identity provider seamlessly in the background. This ensures active browser sessions are kept alive transparently without forcing interactive user logins or page refreshes.

### 🌐 Proxy Trapping & Host Routing
**Q: Does enabling the corporate proxy trap local incoming routes?**  
**A:** No. Specifying the `AUTH_CORE_PROXY_HOST` wraps only the outbound server-to-server identity handshakes (such as JWKS verification and token exchange endpoints). It remains completely isolated from, and ignores, incoming internal platform requests, load balancers, or proxy mappings. You can use the `AUTH_CORE_NO_PROXY` bypass array to explicitly exclude local internal services.

### ⏱️ Distributed Clock Drift & Leeway
**Q: How do we prevent token verification failures due to server clock drift?**  
**A:** Distributed architectures like Kubernetes can experience clock drift across worker nodes. To guarantee high availability and prevent premature validation rejections, `auth-core` applies a default **60-second leeway buffer** during all JWT `iat`, `nbf`, and `exp` validations.

---

## 📄 License

MIT © Saurabh Verma
