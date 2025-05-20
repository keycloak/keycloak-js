// callbackStorage.ts
const STORAGE_KEY_PREFIX = "kc-callback-";

export interface ICallbackStorage {
  get(state: string): any;
  add(state: any): void;
  removeItem?(key: string): void;
}

export class LocalStorageCallbackStorage implements ICallbackStorage {
  get(state: string): any {
    if (!state) return undefined;
    const key = STORAGE_KEY_PREFIX + state;
    let value = localStorage.getItem(key);
    if (value) {
      localStorage.removeItem(key);
      value = JSON.parse(value);
    }
    this.clearInvalidValues();
    return value;
  }

  add(state: any): void {
    this.clearInvalidValues();
    const key = STORAGE_KEY_PREFIX + state.state;
    const value = JSON.stringify({
      ...state,
      expires: Date.now() + 60 * 60 * 1000,
    });
    try {
      localStorage.setItem(key, value);
    } catch {
      this.clearAllValues();
      localStorage.setItem(key, value);
    }
  }

  private clearInvalidValues(): void {
    const currentTime = Date.now();
    for (const [key, value] of Object.entries(localStorage)) {
      if (!key.startsWith(STORAGE_KEY_PREFIX)) continue;
      const expiry = this.parseExpiry(value as string);
      if (expiry === null || expiry < currentTime) {
        localStorage.removeItem(key);
      }
    }
  }

  private clearAllValues(): void {
    for (const [key] of Object.entries(localStorage)) {
      if (key.startsWith(STORAGE_KEY_PREFIX)) {
        localStorage.removeItem(key);
      }
    }
  }

  private parseExpiry(value: string): number | null {
    let parsed: any;
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
    if (
      typeof parsed === "object" &&
      "expires" in parsed &&
      typeof parsed.expires === "number"
    ) {
      return parsed.expires;
    }
    return null;
  }
}

export class CookieCallbackStorage implements ICallbackStorage {
  get(state: string): any {
    if (!state) return undefined;
    const value = this.getCookie(STORAGE_KEY_PREFIX + state);
    this.setCookie(STORAGE_KEY_PREFIX + state, "", this.cookieExpiration(-100));
    if (value) {
      return JSON.parse(value);
    }
    return undefined;
  }

  add(state: any): void {
    this.setCookie(
      STORAGE_KEY_PREFIX + state.state,
      JSON.stringify(state),
      this.cookieExpiration(60),
    );
  }

  removeItem(key: string): void {
    this.setCookie(key, "", this.cookieExpiration(-100));
  }

  private cookieExpiration(minutes: number): Date {
    const exp = new Date();
    exp.setTime(exp.getTime() + minutes * 60 * 1000);
    return exp;
  }

  private getCookie(key: string): string {
    const name = key + "=";
    const ca = document.cookie.split(";");
    for (const c0 of ca) {
      let c = c0;
      while (c.charAt(0) === " ") c = c.substring(1);
      if (c.indexOf(name) === 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
  }

  private setCookie(key: string, value: string, expiration: Date): void {
    document.cookie =
      key + "=" + value + "; " + "expires=" + expiration.toUTCString() + "; ";
  }
}

export const createCallbackStorage = (): ICallbackStorage => {
  try {
    return new LocalStorageCallbackStorage();
  } catch {
    return new CookieCallbackStorage();
  }
};
