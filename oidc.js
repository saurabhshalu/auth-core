import express from "express";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";
import jwkToPem from "jwk-to-pem";

export function setupOidc(app, config) {
    const common = config.common || {};
    const oidc = config.oidc || {};

    const getFetchOptions = () => (config.proxy?.enabled ? { agent: app.locals.proxyAgent } : {});

    async function fetchJwks() {
        const resp = await fetch(`${oidc.issuer}/protocol/openid-connect/certs`, getFetchOptions());
        if (!resp.ok) throw new Error("Failed to fetch JWKS");
        return await resp.json();
    }

    async function verifyJwt(token, jwks) {
        const { header } = jwt.decode(token, { complete: true });
        const jwk = jwks.keys.find(k => k.kid === header.kid);
        if (!jwk) throw new Error("No matching JWK found");
        const pem = jwkToPem(jwk);
        return jwt.verify(token, pem, { algorithms: [header.alg || "RS256"] });
    }

    app.get(`${common.appBasePath}/callback`, async (req, res) => {
        try {
            const code = req.query.code;
            if (!code) return res.status(400).send("Missing code");

            const params = new URLSearchParams({
                grant_type: "authorization_code",
                code,
                redirect_uri: oidc.redirectUri,
                client_id: oidc.clientId,
            });
            if (oidc.clientSecret) params.append("client_secret", oidc.clientSecret);
            if (oidc.enablePKCE && req.session.pkceVerifier) params.append("code_verifier", req.session.pkceVerifier);

            const options = { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: params, ...getFetchOptions() };
            const tokenResp = await fetch(`${oidc.issuer}/protocol/openid-connect/token`, options);
            if (!tokenResp.ok) throw new Error(`Token request failed: ${tokenResp.status}`);
            const tokens = await tokenResp.json();

            const jwks = await fetchJwks();
            const decoded = await verifyJwt(tokens.id_token, jwks);

            req.session.tokens = tokens;
            req.session.user = {
                username: decoded.preferred_username || decoded.sub,
                email: decoded.email || null,
                roles: decoded.roles || null,
                raw: decoded
            };

            res.redirect(common.appBasePath || "/");

        } catch (err) {
            console.error(err);
            res.status(500).send("Login failed");
        }
    });

    app.get(`${common.appBasePath}/logout`, (req, res) => {
        const idToken = req.session.tokens?.id_token;
        req.session.destroy(() => {
            const redirectUri = common.postLogoutRedirectUri || common.appBasePath;
            let logoutUrl = `${oidc.issuer}/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(redirectUri)}`;
            if (idToken) logoutUrl += `&id_token_hint=${encodeURIComponent(idToken)}`;
            res.redirect(logoutUrl);
        });
    });


    app.post(`${common.appBasePath}/backchannel-logout`, express.json(), async (req, res) => {
        try {
            const logoutToken = req.body.logout_token;
            if (!logoutToken) return res.status(400).send("Missing logout_token");
            const jwks = await fetchJwks();
            await verifyJwt(logoutToken, jwks);
            req.session.destroy(() => res.sendStatus(200));
        } catch (err) {
            console.error(err);
            res.sendStatus(400);
        }
    });

    app.get(`${common.appBasePath}/refresh`, async (req, res) => {
        try {
            if (!req.session.tokens?.refresh_token) return res.status(400).send("No refresh token");
            const params = new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: req.session.tokens.refresh_token,
                client_id: oidc.clientId
            });
            if (oidc.clientSecret) params.append("client_secret", oidc.clientSecret);

            const options = { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: params, ...getFetchOptions() };
            const tokenResp = await fetch(`${oidc.issuer}/protocol/openid-connect/token`, options);
            if (!tokenResp.ok) throw new Error(`Refresh token failed: ${tokenResp.status}`);
            const tokens = await tokenResp.json();
            req.session.tokens = tokens;
            res.send(tokens);
        } catch (err) {
            console.error(err);
            res.status(500).send("Refresh failed");
        }
    });
}
