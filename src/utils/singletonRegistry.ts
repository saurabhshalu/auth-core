// src/utils/singletonRegistry.ts
//
// Cross-format globalThis registry.
// When both ESM and CJS builds of this library are loaded in the same process
// (dual-package hazard), module-level variables produce two separate instances.
// globalThis is shared across all module systems in the same process, so this
// registry acts as the single source of truth for all process-wide singletons.

const REGISTRY_KEY = Symbol.for("authcore.v1.registry");

interface Registry {
  otelStarted?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  otelSdk?: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  axiosSingleton?: any;
}

function getRegistry(): Registry {
  const g = globalThis as Record<symbol, Registry>;
  if (g[REGISTRY_KEY] == null) {
    g[REGISTRY_KEY] = {};
  }
  return g[REGISTRY_KEY]!;
}

export const registry = {
  get<K extends keyof Registry>(key: K): Registry[K] {
    return getRegistry()[key];
  },
  set<K extends keyof Registry>(key: K, value: Registry[K]): void {
    getRegistry()[key] = value;
  },
  has(key: keyof Registry): boolean {
    return key in getRegistry();
  },
};
