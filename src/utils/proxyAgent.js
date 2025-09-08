import { HttpsProxyAgent } from "https-proxy-agent";

export function createProxyAgent(proxyConfig) {
    if (!proxyConfig?.enabled) return undefined;
    const proxyUrl = `${proxyConfig.host}:${proxyConfig.port}`;
    const agent = new HttpsProxyAgent(proxyUrl);
    if (proxyConfig.auth) agent.options.auth = proxyConfig.auth;
    return agent;
}
