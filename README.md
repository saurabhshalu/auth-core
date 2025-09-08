# @saurabhshalu/auth-core

Central authentication middleware for **Express.js** applications with support for **OIDC (OpenID Connect)** and **CAS (Central Authentication Service)**.  
It provides a simple way to plug authentication into your Node.js apps with session management, a `/me` (or custom) endpoint, and route protection.

---

## ✨ Features

- ✅ Supports **OIDC (Keycloak, Azure AD, etc.)**
- ✅ Supports **CAS**
- ✅ Pluggable auth modes: `OIDC`, `CAS`, or `NONE`
- ✅ Session-based authentication with `express-session`
- ✅ Built-in `/me` (or custom endpoint) to fetch user details
- ✅ Built-in `/logout`, `/refresh`, and backchannel logout support
- ✅ Supports proxy configuration
- ✅ Hooks to **enrich session** or **extend `/me` response**

---

## 📦 Installation

```bash
npm install @saurabhshalu/auth-core
```

---

## 🚀 Usage

### Basic Setup

```js
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { setupAuth, protect } from "@saurabhshalu/auth-core";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Config for auth library
const config = {
  common: {
    appBasePath: "/app-name",
    authMode: "OIDC", // "OIDC" | "CAS" | "NONE"
    sessionSecret: "LONG_SECRET",
    //excludePathFromProtect: ["/additional/path/needs/to/be/excluded/from/protect"],
    // meEndpointContext: "/userReport", // defaults to "/me"
  },
  oidc: {
    issuer: "https://domain.com/keycloak/realms/tcshobs",
    clientId: "app-name",
    redirectUri: "https://domain.com/app-name/callback",
  },
  cas: {
    dnsName: "https://domain.com",
  },
  proxy: {
    enabled: false,
  },
  enrichMe: async (session) => {
    return { custom: "value from enrichMe" };
  },
  enrichSession: async (session) => {
    session.user.extra = "extra info from enrichSession";
  },
};

// Setup auth
setupAuth(app, config);

// Protect all routes under appBasePath
app.use(config.common.appBasePath, protect(config));

// Example: serve SPA
app.use(
  config.common.appBasePath,
  express.static(path.join(__dirname, "public"))
);
app.get(config.common.appBasePath, (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

// Start server
app.listen(4775, () =>
  console.log("app-name running on http://localhost:4775/app-name")
);
```

---

## ⚙️ Configuration

### `common`

| Key                     | Type   | Default         | Description                                             |
| ----------------------- | ------ | --------------- | ------------------------------------------------------- |
| `appBasePath`           | string | `/app`          | Base path for app and auth routes                       |
| `authMode`              | string | `"OIDC"`        | Authentication mode: `"OIDC"`, `"CAS"`, `"NONE"`        |
| `sessionSecret`         | string | required        | Secret for `express-session`                            |
| `sessionName`           | string | `"NSESSIONID"`  | Cookie name                                             |
| `environment`           | string | `"DEVELOPMENT"` | `"PRODUCTION"` makes cookies secure                     |
| `postLogoutRedirectUri` | string | `appBasePath`   | Redirect after logout                                   |
| `meEndpointContext`     | string | `"/me"`         | Endpoint path for user info (e.g. `/me`, `/userReport`) |

### `oidc`

| Key                   | Type   | Required                 | Description                      |
| --------------------- | ------ | ------------------------ | -------------------------------- |
| `issuer`              | string | ✅                       | OIDC provider base URL           |
| `clientId`            | string | ✅                       | OIDC client ID                   |
| `clientSecret`        | string | ❌                       | OIDC client secret (if required) |
| `redirectUri`         | string | ✅                       | Redirect URL after login         |
| `enablePKCE`          | bool   | ❌                       | Enable PKCE flow                 |
| `codeChallengeMethod` | string | `"S256"`                 | PKCE challenge method            |
| `scope`               | string | `"openid profile email"` | OIDC scopes                      |

### `cas`

| Key       | Type   | Required | Description                                                      |
| --------- | ------ | -------- | ---------------------------------------------------------------- |
| `dnsName` | string | ✅       | CAS server base URL                                              |
| `paths`   | object | ❌       | Override default CAS paths (`login`, `logout`, `validate`, etc.) |

### `proxy`

| Key       | Type   | Default | Description        |
| --------- | ------ | ------- | ------------------ |
| `enabled` | bool   | false   | Enable proxy agent |
| `host`    | string | —       | Proxy hostname     |
| `port`    | number | —       | Proxy port         |

### Hooks

- **`enrichMe(session)`** → Extend `/me` (or custom endpoint) response
- **`enrichSession(session)`** → Add extra fields into session after login

---

## 🔐 Provided Endpoints

- `GET /appBasePath/login` → (CAS) login
- `GET /appBasePath/callback` → (OIDC) login callback
- `GET /appBasePath/logout` → logout and redirect
- `POST /appBasePath/backchannel-logout` → (OIDC) backchannel logout
- `GET /appBasePath/refresh` → refresh OIDC tokens
- `GET /appBasePath/<meEndpointContext>` → get logged-in user info (default: `/me`)

---

## 🛡️ Protecting Routes

Use `protect(config)` middleware to ensure routes require authentication.

```js
app.use("/app-name/private", protect(config), (req, res) => {
  res.send("This is protected!");
});
```

---

## 📜 License

MIT © [Saurabh Verma](mailto:skvermacodes@gmail.com)
