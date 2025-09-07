import ConnectCas from "connect-cas2";

export function setupCas(app, config) {
    const common = config.common || {};

    const casClient = new ConnectCas({
        ignore: config.cas?.ignore || [],
        match: config.cas?.match || [],
        servicePrefix: config.cas.dnsName,
        serverPath: config.cas.dnsName,
        paths: {
            login: "/cas/login",
            logout: "/cas/logout",
            validate: `${config.appBasePath}/validate`,
            serviceValidate: "/cas/serviceValidate",
            proxy: false,
            proxyCallback: false,
            ...(config.cas?.paths || {})
        },
        slo: config.cas?.slo !== false,
        restletIntegration: false,
    });

    app.get(`${common.appBasePath}/login`, (req, res) => {
        res.send(`Hello ${req.session.cas?.user}`);
    });

    app.use(casClient.core());

    // Normalize session
    app.use((req, res, next) => {
        if (req.session.cas && !req.session.user) {

            req.session.user = {
                username: req.session.cas.user,
                email: null,
                roles: null,
                raw: { ...req.session.cas }
            };
        }
        next();
    });

    app.get(`${common.appBasePath}/logout`, (req, res) => {
        const redirectUri = common.postLogoutRedirectUri || `${config.cas.dnsName}${common.appBasePath}`;
        req.session.destroy(() => {
            const logoutUrl = `${config.cas.paths.logout}?service=${encodeURIComponent(
                redirectUri
            )}`;
            res.redirect(logoutUrl);
        });
    });
}