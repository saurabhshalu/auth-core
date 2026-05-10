// src/utils/delegatingStore.ts
import session from "express-session";
import type { Store, SessionData } from "express-session";

type GetCallback = (err: unknown, session?: SessionData | null) => void;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyCallback = (...args: any[]) => void;

type StoreGetter = () => Store | undefined;

/**
 * A session store that delegates all operations to another store obtained lazily.
 * Used to allow async Redis initialization while express-session (sync constructor)
 * already needs a store reference.
 */
export default class DelegatingStore extends session.Store {
  private readonly _getStore: StoreGetter;

  constructor(getStoreFn: StoreGetter) {
    super();
    this._getStore = getStoreFn;
  }

  private _withStore(cb: (err: Error | null, store?: Store) => void): void {
    const store = this._getStore();
    if (!store) {
      cb(new Error("[auth-core] Session store not ready"));
      return;
    }
    cb(null, store);
  }

  get(sid: string, cb: GetCallback): void {
    this._withStore((e, s) => (e ? cb(e) : s!.get(sid, cb)));
  }

  set(sid: string, sessionData: SessionData, cb?: AnyCallback): void {
    this._withStore((e, s) => (e ? cb?.(e) : s!.set(sid, sessionData, cb)));
  }

  destroy(sid: string, cb?: AnyCallback): void {
    this._withStore((e, s) => (e ? cb?.(e) : s!.destroy(sid, cb)));
  }

  touch(sid: string, sessionData: SessionData, cb?: AnyCallback): void {
    this._withStore((e, s) => {
      if (e) {
        cb?.(e);
        return;
      }
      if (typeof s!.touch === "function") {
        s!.touch(sid, sessionData, cb);
      } else {
        cb?.();
      }
    });
  }
}
