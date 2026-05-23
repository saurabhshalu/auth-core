// src/utils/otel.ts
//
// OpenTelemetry bootstrap for Node.js apps.
// Call as early as possible (before importing express/mysql2/pg/redis/etc).
//
// For apps bundled with ncc, use the preload instead:
//   node --require @saurabhshalu/auth-core/otel-preload dist/bundle.js

import { NodeSDK } from "@opentelemetry/sdk-node";
import {
  resourceFromAttributes,
  detectResources,
  envDetector,
  processDetector,
} from "@opentelemetry/resources";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";
import { getNodeAutoInstrumentations } from "@opentelemetry/auto-instrumentations-node";
import { PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-proto";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-proto";
import { diag, DiagConsoleLogger, DiagLogLevel, trace as otelTrace } from "@opentelemetry/api";
import { registry } from "./singletonRegistry.js";
import type { OtelOptions, OtelHandle, TraceHelper } from "../types.js";

// -----------------------------------------------------------------------------

function otel(opts: OtelOptions = {}): OtelHandle {
  // ✅ globalThis-based guard prevents duplicate SDK in dual-package scenarios
  if (registry.get("otelStarted")) {
    const sdk = registry.get("otelSdk") as NodeSDK | undefined;
    return { shutdown: () => sdk?.shutdown() ?? Promise.resolve() };
  }

  const {
    serviceName = process.env["OTEL_SERVICE_NAME"] ?? inferServiceName(),
    serviceVersion = process.env["OTEL_SERVICE_VERSION"],
    endpoint = normalizeEndpoint(
      process.env["OTEL_EXPORTER_OTLP_ENDPOINT"] ?? "http://localhost:4318",
    ),
    headers = parseHeaders(process.env["OTEL_EXPORTER_OTLP_HEADERS"]),
    enableMetrics = envBool(process.env["OTEL_ENABLE_METRICS"], true),
    enableTraces = envBool(process.env["OTEL_ENABLE_TRACES"], true),
    metricsIntervalMs = Number(process.env["OTEL_METRICS_INTERVAL_MS"]) ||
      60_000,
    instrumentations = defaultInstrumentationOverrides(),
    logLevel = (process.env["OTEL_INTERNAL_LOG_LEVEL"] ??
      "warn") as OtelOptions["logLevel"],
  } = opts;

  setDiagLevel(logLevel ?? "warn");

  const detectedResource = detectResources({
    detectors: [envDetector, processDetector],
  });
  const resource = detectedResource.merge(
    resourceFromAttributes({
      [ATTR_SERVICE_NAME]: serviceName,
      [ATTR_SERVICE_VERSION]: serviceVersion ?? "0.0.0",
    }),
  );

  const traceExporter = enableTraces
    ? new OTLPTraceExporter({
        url: (endpoint as { traces: string }).traces,
        headers,
      })
    : undefined;

  const metricReader = enableMetrics
    ? new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({
          url: (endpoint as { metrics: string }).metrics,
          headers,
        }),
        exportIntervalMillis: metricsIntervalMs,
      })
    : undefined;

  const sdkInstance = new NodeSDK({
    resource,
    traceExporter,
    metricReader,
    instrumentations: [getNodeAutoInstrumentations(instrumentations)],
  });

  try {
    sdkInstance.start();

    registry.set("otelStarted", true);
    registry.set("otelSdk", sdkInstance);

    const shutdown = async (): Promise<void> => {
      try {
        await sdkInstance.shutdown();
      } catch (err) {
        diag.warn("[otel] shutdown error", err);
      }
    };

    process.once("SIGTERM", shutdown);
    process.once("SIGINT", shutdown);

    return { shutdown };
  } catch (err) {
    diag.error("[otel] failed to start", err);
    throw err;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function inferServiceName(): string {
  if (process.env["npm_package_name"]) return process.env["npm_package_name"];
  const main = process.argv?.[1] ?? process.env["_"] ?? "node-service";
  const base = String(main).split("/").pop() ?? String(main);
  return base.replace(/\.(js|cjs|mjs)$/i, "");
}

interface NormalizedEndpoint {
  traces: string;
  metrics: string;
}

function normalizeEndpoint(base: string): NormalizedEndpoint {
  const hasPath = /\/v1\/(traces|metrics)/.test(base);
  const b = String(base).replace(/\/$/, "");
  const traces = hasPath
    ? b.replace(/\/v1\/metrics$/, "/v1/traces")
    : `${b}/v1/traces`;
  const metrics = hasPath
    ? b.replace(/\/v1\/traces$/, "/v1/metrics")
    : `${b}/v1/metrics`;
  return { traces, metrics };
}

function parseHeaders(str = ""): Record<string, string> {
  const result: Record<string, string> = {};
  for (const pair of str.split(",")) {
    const p = pair.trim();
    if (!p) continue;
    const idx = p.indexOf("=");
    if (idx < 0) result[p] = "";
    else result[p.slice(0, idx).trim()] = p.slice(idx + 1).trim();
  }
  return result;
}

function envBool(val: string | undefined, defaultVal: boolean): boolean {
  if (val == null) return defaultVal;
  return ["1", "true", "yes", "on"].includes(String(val).toLowerCase());
}

function setDiagLevel(level: OtelOptions["logLevel"]): void {
  const map: Record<string, DiagLogLevel> = {
    none: DiagLogLevel.NONE,
    error: DiagLogLevel.ERROR,
    warn: DiagLogLevel.WARN,
    info: DiagLogLevel.INFO,
    debug: DiagLogLevel.DEBUG,
  };
  diag.setLogger(
    new DiagConsoleLogger(),
    map[String(level ?? "warn").toLowerCase()] ?? DiagLogLevel.WARN,
  );
}

function defaultInstrumentationOverrides(): Record<string, object> {
  return {
    "@opentelemetry/instrumentation-http": { enabled: true },
    "@opentelemetry/instrumentation-undici": { enabled: true },
    "@opentelemetry/instrumentation-express": { enabled: true },
    "@opentelemetry/instrumentation-fastify": { enabled: true },
    "@opentelemetry/instrumentation-koa": { enabled: true },
    "@opentelemetry/instrumentation-graphql": { enabled: true },
    "@opentelemetry/instrumentation-aws-sdk": { enabled: true },
    "@opentelemetry/instrumentation-mysql": { enabled: true },
    "@opentelemetry/instrumentation-mysql2": { enabled: true },
    "@opentelemetry/instrumentation-pg": { enabled: true },
    "@opentelemetry/instrumentation-mongodb": { enabled: true },
    "@opentelemetry/instrumentation-redis": { enabled: true },
    "@opentelemetry/instrumentation-kafkajs": { enabled: true },
    "@opentelemetry/instrumentation-amqplib": { enabled: true },
    "@opentelemetry/instrumentation-winston": { enabled: true },
    "@opentelemetry/instrumentation-pino": { enabled: true },
  };
}

export const trace: TraceHelper = {
  setAttributes(attributes: Record<string, any>): void {
    try {
      const span = otelTrace.getActiveSpan();
      if (!span || typeof span.setAttributes !== "function") return;

      const validAttrs: Record<string, any> = {};
      for (const [key, val] of Object.entries(attributes)) {
        if (val !== undefined && val !== null) {
          validAttrs[key] = val;
        }
      }

      if (Object.keys(validAttrs).length > 0) {
        span.setAttributes(validAttrs);
      }
    } catch (err) {
      // Safe no-op on any error
    }
  },

  addEvent(name: string, attributes?: Record<string, any>): void {
    try {
      const span = otelTrace.getActiveSpan();
      if (!span || typeof span.addEvent !== "function") return;

      if (attributes) {
        const validAttrs: Record<string, any> = {};
        for (const [key, val] of Object.entries(attributes)) {
          if (val !== undefined && val !== null) {
            validAttrs[key] = val;
          }
        }
        span.addEvent(name, validAttrs);
      } else {
        span.addEvent(name);
      }
    } catch (err) {
      // Safe no-op on any error
    }
  },
};

export default otel;

