// src/types/connect-cas2.d.ts
// Local type shim — no @types/connect-cas2 exists on npm.
declare module 'connect-cas2' {
  import type { RequestHandler } from 'express';

  interface ConnectCasOptions {
    servicePrefix: string;
    serverPath: string;
    paths?: {
      login?: string;
      logout?: string;
      validate?: string;
      serviceValidate?: string;
      proxy?: string | false;
      proxyCallback?: string | false;
    };
    ignore?: string[];
    match?: string[];
    slo?: boolean;
    restletIntegration?: boolean;
    [key: string]: unknown;
  }

  interface ConnectCasInstance {
    core(): RequestHandler;
  }

  class ConnectCas {
    constructor(options: ConnectCasOptions);
    core(): RequestHandler;
  }

  export = ConnectCas;
}
