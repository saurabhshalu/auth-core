import session from "express-session";
import { setupOidc } from "./oidc.js";
import { setupCas } from "./cas.js";
import { createProxyAgent } from "./utils/proxyAgent.js";

export function setupAuth(app, config) {
    if (!app || !config) throw new Error("app and config required");

    const common = config.common || {};

    // Proxy agent setup
    const agent = createProxyAgent(config.proxy);
    if (agent) app.locals.proxyAgent = agent;

    const mode = (common.authMode || "OIDC").toUpperCase();
    if (mode === "NONE") {
        console.log("[auth] AUTH_MODE=NONE → skipping authentication setup.");
        // no-op: just a passthrough middleware so apps don’t break
        app.use((req, res, next) => next());
        return;
    }

    // Single express-session setup
    app.use(session({
        name: common.sessionName || "NSESSIONID",
        secret: common.sessionSecret || "LONG_SECRET_KEY",
        resave: false,
        saveUninitialized: true,
        cookie: { secure: common.environment !== 'DEVELOPMENT', sameSite: "lax" }
    }));


    if (mode === "OIDC") setupOidc(app, config);
    else if (mode === "CAS") setupCas(app, config);
    else throw new Error(`Unsupported authMode: ${mode}`);

    // /me route centralized
    const appBase = common.appBasePath || "/app";
    app.get(`${appBase}${common.meEndpointContext || "/me"}`, async (req, res) => {
        if (!req.session.user) return res.status(401).send({ error: "Not authenticated" });
        const extraData = typeof config.enrichMe === "function" ? await config.enrichMe(req.session) : {};
        res.send({ ...req.session.user, ...extraData });
    });
}

// Protect middleware
export function protect(config) {
    const appBase = config.common?.appBasePath || "/app";

    const internalPaths = [
        `${appBase}/callback`,
        `${appBase}/backchannel-logout`,
        `${appBase}/cas/validate`,
        `${appBase}/cas/serviceValidate`,
        ...(config.common?.excludePathFromProtect || [])
    ];

    return async function (req, res, next) {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');

        if (internalPaths.includes(req.path)) return next();

        const mode = (config.common?.authMode || "OIDC").toUpperCase();
        let authenticated = false;


        if (req.session.user) authenticated = true;
        else if (mode === "OIDC") authenticated = req.session?.tokens?.access_token;
        else if (mode === "CAS") authenticated = req.session?.cas?.name;

        if (!authenticated) {
            if (mode === "OIDC") {
                const oidc = config.oidc;
                let url = `${oidc.issuer}/protocol/openid-connect/auth?client_id=${encodeURIComponent(oidc.clientId)}&redirect_uri=${encodeURIComponent(oidc.redirectUri)}&response_type=code&scope=${encodeURIComponent(oidc.scope || "openid profile email")}`;

                if (oidc.enablePKCE) {
                    const crypto = await import("crypto");
                    const codeVerifier = crypto.randomBytes(64).toString("base64url");
                    req.session.pkceVerifier = codeVerifier;
                    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
                    url += `&code_challenge=${codeChallenge}&code_challenge_method=${encodeURIComponent(oidc.codeChallengeMethod || "S256")}`;
                }

                return res.redirect(url);
            }

            if (mode === "CAS") {
                const casLoginUrl = `${config.cas?.dnsName}${config.cas?.paths?.login || "/cas/login"}?service=${encodeURIComponent(req.originalUrl)}`;
                return res.redirect(casLoginUrl);
            }
        }

        // Run enrichSession once per session
        if (typeof config.enrichSession === "function" && !req.session._enriched) {
            try {
                console.log("Enriching session...");
                await config.enrichSession(req.session);
                req.session._enriched = true;
            } catch (err) {
                console.error("Failed to enrich session:", err);
            }
        }

        next();
    };
}
