// src/utils/proxyAgent.ts
import axios, {
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from "axios";
import { HttpsProxyAgent } from "https-proxy-agent";
import { URL } from "node:url";
import { registry } from "./singletonRegistry.js";
import type { AuthConfig, ProxyConfig } from "../types.js";

// ── NO_PROXY parsing & matching ──────────────────────────────────────────────

function parseNoProxyInput(input: string | string[] | undefined): string[] {
  if (!input) return [];
  if (Array.isArray(input))
    return input
      .map(String)
      .map((s) => s.trim())
      .filter(Boolean);
  return String(input)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function getEnvNoProxy(): string {
  return process.env["NO_PROXY"] ?? process.env["no_proxy"] ?? "";
}

type UrlMatcher = (targetUrl: string) => boolean;

function compileNoProxyMatcher(config?: AuthConfig): UrlMatcher {
  const envNoProxy = getEnvNoProxy();
  const rules = [
    ...parseNoProxyInput(envNoProxy),
    ...parseNoProxyInput(config?.proxy?.noProxy),
  ]
    .map((s) => s.toLowerCase())
    .filter(Boolean);

  if (rules.includes("*")) return () => true;

  const exactHosts = new Set<string>();
  const exactHostPorts = new Set<string>();
  const suffixes: string[] = [];

  for (const rule of rules) {
    if (rule.includes(":")) {
      exactHostPorts.add(rule);
      continue;
    }
    const host = rule.startsWith(".") ? rule.slice(1) : rule;
    exactHosts.add(host);
    suffixes.push(host);
  }

  return (targetUrl: string): boolean => {
    if (!targetUrl) return false;
    let u: URL;
    try {
      u = new URL(targetUrl);
    } catch {
      return false;
    }

    const host = u.hostname.toLowerCase();
    const port =
      u.port ||
      (u.protocol === "https:" ? "443" : u.protocol === "http:" ? "80" : "");
    const hp = port ? `${host}:${port}` : host;

    if (exactHostPorts.has(hp)) return true;
    if (exactHosts.has(host)) return true;
    for (const sf of suffixes) {
      if (!sf) continue;
      if (host === sf || host.endsWith(`.${sf}`)) return true;
    }
    return false;
  };
}

// ── Proxy agent creation ─────────────────────────────────────────────────────

function createProxyAgent(
  proxyConfig?: ProxyConfig,
): HttpsProxyAgent<string> | undefined {
  if (!proxyConfig?.enabled) return undefined;
  const { host, port, protocol = "http", auth } = proxyConfig;
  if (!host || !port) return undefined;

  const creds = auth?.username
    ? `${encodeURIComponent(auth.username)}:${encodeURIComponent(auth.password ?? "")}@`
    : "";
  const proxyUrl = `${protocol}://${creds}${host}:${port}`;
  return new HttpsProxyAgent(proxyUrl);
}

// ── Singleton axios instance ─────────────────────────────────────────────────

interface AxiosSingleton {
  axios: AxiosInstance;
  agent: HttpsProxyAgent<string> | undefined;
  matcher: UrlMatcher;
  proxyEnabled: boolean;
}

function buildAxiosSingleton(config: AuthConfig): AxiosSingleton {
  const proxyEnabled = !!config?.proxy?.enabled;
  const agent = createProxyAgent(config?.proxy);
  const shouldBypass = compileNoProxyMatcher(config);

  const instance = axios.create();

  if (proxyEnabled && agent) {
    instance.interceptors.request.use((req: InternalAxiosRequestConfig) => {
      try {
        const fullUrl = new URL(
          req.url ?? "",
          req.baseURL ??
            (req.headers?.["host"]
              ? `https://${String(req.headers["host"])}`
              : undefined),
        ).toString();

        if (shouldBypass(fullUrl)) {
          (
            req as InternalAxiosRequestConfig & { httpsAgent?: unknown }
          ).httpsAgent = undefined;
          (req as InternalAxiosRequestConfig & { proxy?: unknown }).proxy =
            false;
        } else {
          (
            req as InternalAxiosRequestConfig & { httpsAgent?: unknown }
          ).httpsAgent = agent;
          (req as InternalAxiosRequestConfig & { proxy?: unknown }).proxy =
            false;
        }
      } catch {
        (
          req as InternalAxiosRequestConfig & { httpsAgent?: unknown }
        ).httpsAgent = undefined;
      }
      return req;
    });
  }

  return { axios: instance, agent, matcher: shouldBypass, proxyEnabled };
}

/**
 * Returns a cached Axios instance with NO_PROXY-aware proxy interceptor.
 * Uses the globalThis registry to survive dual-package hazard.
 */
export function getAxios(config: AuthConfig): AxiosInstance {
  const cached = registry.get("axiosSingleton") as AxiosSingleton | undefined;
  if (cached) return cached.axios;

  const singleton = buildAxiosSingleton(config);
  registry.set("axiosSingleton", singleton);
  return singleton.axios;
}

export function getFetchOptionsFor(
  url: string,
  config: AuthConfig,
): Record<string, unknown> {
  const cached = registry.get("axiosSingleton") as AxiosSingleton | undefined;
  const agent = cached?.agent ?? createProxyAgent(config?.proxy);
  const shouldBypass = cached?.matcher ?? compileNoProxyMatcher(config);
  if (!config?.proxy?.enabled || !agent) return {};
  return shouldBypass(url) ? {} : { httpsAgent: agent };
}

export function getProxyAgent(
  config: AuthConfig,
): HttpsProxyAgent<string> | undefined {
  const cached = registry.get("axiosSingleton") as AxiosSingleton | undefined;
  return cached?.agent ?? createProxyAgent(config?.proxy);
}

// For testing
export const __internals = { parseNoProxyInput, compileNoProxyMatcher };
