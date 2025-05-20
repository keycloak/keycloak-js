import {
  randomUUID,
  randomBytes,
  createHash,
  getRandomValues,
  subtle,
  type BinaryLike,
  type BinaryToTextEncoding,
  type Hash,
} from "crypto";
import type {
  IAccessTokenResponse,
  IJsonConfig,
  IKeycloakAccountOptions,
  IKeycloakAdapter,
  IKeycloakConfig,
  IKeycloakInitOptions,
  IKeycloakLoginOptions,
  IKeycloakLogoutOptions,
  IKeycloakProfile,
  IKeycloakRegisterOptions,
  INetworkErrorOptions,
  IOpenIdProviderMetadata,
  KeycloakFlow,
  KeycloakOnLoad,
  KeycloakResponseMode,
  KeycloakResponseType,
  KeycloakPkceMethod,
  KeycloakLogoutMethod,
} from "./types.ts";
import type { IEndpoints } from "./helpers.ts";

const CONTENT_TYPE_JSON: "application/json" = "application/json";
const STORAGE_KEY_PREFIX: "kc-callback-" = "kc-callback-";

const isObject = <T extends Record<string, unknown>>(
  val: unknown,
): val is T => typeof val === "object" && val !== null;

const arrayHas = <T>(arr: readonly T[], val: T): boolean => arr.includes(val);

const base64UrlDecode = (input: string): string => {
  let output: string = input.replace(/-/g, "+").replace(/_/g, "/");
  switch (output.length % 4) {
    case 2:
      output += "==";
      break;
    case 3:
      output += "=";
      break;
  }
  try {
    return atob(output);
  } catch {
    if (typeof Buffer !== "undefined") {
      return Buffer.from(output, "base64" as BinaryToTextEncoding).toString(
        "utf-8",
      );
    }
    throw new Error("Unable to decode base64url input");
  }
};

// Not directly used by Keycloak logic but could be a utility.
// If unused, consider removing. For now, keep and type.
const b64DecodeUnicode = (input: string): string => {
  return decodeURIComponent(
    atob(input)
      .split("")
      .map((char: string): string => {
        return "%" + ("00" + char.charCodeAt(0).toString(16)).slice(-2);
      })
      .join(""),
  );
};

const decodeToken = (token: string): Record<string, unknown> => {
  const parts: string[] = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Token is not a valid JWT");
  }
  const decodedPayload: string = base64UrlDecode(parts[1]);
  try {
    return JSON.parse(decodedPayload) as Record<string, unknown>;
  } catch {
    throw new Error("Unable to decode token payload");
  }
};

const buildAuthorizationHeader = (token: string): [string, string] => {
  if (!token) {
    throw new Error("Token required for Authorization header");
  }
  return ["Authorization", `Bearer ${token}`];
};

const generateRandomString = (length: number, alphabet: string): string => {
  const randomValues: Uint8Array =
    getRandomValues(new Uint8Array(length)) ?? randomBytes(length);
  return Array.from(
    { length },
    (_, idx: number): string => alphabet[randomValues[idx] % alphabet.length],
  ).join("");
};

const generateCodeVerifier = (length: number): string => {
  return generateRandomString(
    length,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  );
};

const sha256Digest = async (message: string): Promise<ArrayBuffer> => {
  if (typeof subtle !== "undefined" && typeof subtle.digest === "function") {
    return subtle.digest("SHA-256", new TextEncoder().encode(message));
  }
  if (typeof createHash === "function") {
    const hash: Hash = createHash("sha256");
    hash.update(message as BinaryLike);
    return hash.digest().buffer;
  }
  throw new Error("SHA-256 digest not supported in this environment");
};

const bytesToBase64 = (bytes: Uint8Array): string => {
  if (typeof btoa === "function") {
    // In browser environments
    let binary: string = "";
    // This loop is necessary for converting Uint8Array to a binary string for btoa
    for (let i: number = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
  if (typeof Buffer !== "undefined") {
    // In Node.js environments
    return Buffer.from(bytes).toString("base64" as BinaryToTextEncoding);
  }
  throw new Error("Base64 encoding not supported in this environment");
};

const generatePkceChallenge = async (
  pkceMethod: KeycloakPkceMethod | false, // Allow false for type consistency
  codeVerifier: string,
): Promise<string> => {
  if (pkceMethod !== "S256") { // Only S256 is typically supported
    throw new TypeError("Invalid PKCE method, expected S256");
  }
  const hash: Uint8Array = new Uint8Array(await sha256Digest(codeVerifier));
  return bytesToBase64(hash)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

const createUUID = (): string =>
  typeof randomUUID === "function"
    ? randomUUID()
    : generateRandomString(36, "abcdefghijklmnopqrstuvwxyz0123456789");

const createLogger =
  (fn: (...args: string[]) => void) => // Assuming console methods like warn, error
  (...args: string[]): void => {
    if ((globalThis as { enableLogging?: boolean }).enableLogging) {
      fn(...args);
    }
  };

const fetchWithErrorHandling = async (
  url: string,
  init?: RequestInit,
): Promise<Response> => {
  const response: Response = await fetch(url, init);
  if (!response.ok) {
    throw new NetworkError("Server responded with an invalid status.", {
      response,
    });
  }
  return response;
};

const fetchJSON = async <T>(
  url: string,
  init: RequestInit = {},
): Promise<T> => {
  const headers: Headers = new Headers(init.headers);
  headers.set("Accept", CONTENT_TYPE_JSON);
  const response: Response = await fetchWithErrorHandling(url, {
    ...init,
    headers,
  });
  return (await response.json()) as T;
};

interface ICallbackState {
  state: string;
  nonce: string;
  redirectUri: string; // Should be the encoded URI
  loginOptions?: IKeycloakLoginOptions;
  prompt?: KeycloakOnLoad | "none"; // prompt can also be 'none'
  pkceCodeVerifier?: string;
  expires?: number;
}

interface ICallbackStorage {
  get(state: string): ICallbackState | undefined;
  add(state: ICallbackState): void;
}

class LocalStorageCallbackStorage implements ICallbackStorage {
  public get(state: string): ICallbackState | undefined {
    if (!state) {
      return undefined;
    }
    const key: string = STORAGE_KEY_PREFIX + state;
    const value: string | null = localStorage.getItem(key);
    if (value) {
      localStorage.removeItem(key);
      try {
        return JSON.parse(value) as ICallbackState;
      } catch (e) {
        createLogger(console.error)("Failed to parse callback state from localStorage", e instanceof Error ? e.message : String(e));
        return undefined;
      }
    }
    this.#clearInvalidValues();
    return undefined;
  }

  public add(state: ICallbackState): void {
    this.#clearInvalidValues();
    const key: string = STORAGE_KEY_PREFIX + state.state;
    const value: string = JSON.stringify({
      ...state,
      expires: Date.now() + 60 * 60 * 1000, // Expires in 1 hour
    });
    try {
      localStorage.setItem(key, value);
    } catch (error) {
      // If localStorage is full, clear all existing callback values and try again
      this.#clearAllValues();
      try {
        localStorage.setItem(key, value);
      } catch (finalError) {
        createLogger(console.error)(
          "Failed to store callback state in localStorage even after clearing:",
          finalError instanceof Error ? finalError.message : String(finalError),
        );
      }
    }
  }

  #clearInvalidValues(): void {
    const now: number = Date.now();
    Object.entries(localStorage)
      .filter(([key]) => key.startsWith(STORAGE_KEY_PREFIX))
      .forEach(([key, value]) => {
        let parsedValue: Partial<ICallbackState> = {};
        try {
          parsedValue = JSON.parse(value) as Partial<ICallbackState>;
        } catch {
          // If parsing fails, remove the item as it's likely corrupted
          localStorage.removeItem(key);
          return;
        }
        if (
          typeof parsedValue.expires !== "number" ||
          parsedValue.expires < now
        ) {
          localStorage.removeItem(key);
        }
      });
  }

  #clearAllValues(): void {
    Object.keys(localStorage)
      .filter((key: string): boolean => key.startsWith(STORAGE_KEY_PREFIX))
      .forEach((key: string): void => localStorage.removeItem(key));
  }
}

class CookieStorageCallbackStorage implements ICallbackStorage {
  public get(state: string): ICallbackState | undefined {
    if (!state) {
      return undefined;
    }
    const value: string = this.#getCookie(STORAGE_KEY_PREFIX + state);
    this.#setCookie(
      STORAGE_KEY_PREFIX + state,
      "",
      this.#cookieExpiration(-100),
    ); // Delete cookie
    if (value) {
       try {
        return JSON.parse(value) as ICallbackState;
      } catch (e) {
        createLogger(console.error)("Failed to parse callback state from cookie", e instanceof Error ? e.message : String(e));
        return undefined;
      }
    }
    return undefined;
  }

  public add(state: ICallbackState): void {
    this.#setCookie(
      STORAGE_KEY_PREFIX + state.state,
      JSON.stringify(state),
      this.#cookieExpiration(60), // Cookie expires in 60 minutes
    );
  }

  #cookieExpiration(minutes: number): Date {
    const exp: Date = new Date();
    exp.setTime(exp.getTime() + minutes * 60 * 1000); // minutes to milliseconds
    return exp;
  }

  #getCookie(key: string): string {
    const nameEQ: string = key + "=";
    const ca: string[] = document.cookie.split(";");
    for (const cookie of ca) { // Replaced traditional for loop
      let c: string = cookie.trim();
      if (c.startsWith(nameEQ)) {
        return c.substring(nameEQ.length);
      }
    }
    return "";
  }

  #setCookie(key: string, value: string, expirationDate: Date): void {
    const cookieValue: string =
      encodeURIComponent(key) +
      "=" +
      encodeURIComponent(value) +
      ";expires=" +
      expirationDate.toUTCString() +
      ";path=/;SameSite=Lax;Secure"; // Added Secure flag
    document.cookie = cookieValue;
  }
}

const createCallbackStorage = (): ICallbackStorage => {
  try {
    // Test localStorage availability
    localStorage.setItem("kc-test-ls", "test");
    localStorage.removeItem("kc-test-ls");
    return new LocalStorageCallbackStorage();
  } catch (e) {
    createLogger(console.warn)(
      "LocalStorage not available, falling back to CookieStorage.", String(e) // Log the error message
    );
    return new CookieStorageCallbackStorage();
  }
};

// --- NETWORK ERROR ---
// INetworkErrorOptions is already defined in types.ts
export class NetworkError extends Error {
  public response: Response;
  constructor(message: string, options: INetworkErrorOptions) {
    super(message);
    this.response = options.response;
  }
}

// --- ADAPTERS ---

const defaultAdapter = (kc: Keycloak): IKeycloakAdapter => ({
  login: async (options?: IKeycloakLoginOptions): Promise<void> => {
    window.location.assign(await kc.createLoginUrl(options));
  },
  logout: async (options?: IKeycloakLogoutOptions): Promise<void> => {
    const logoutMethod: KeycloakLogoutMethod =
      options?.logoutMethod ?? kc.logoutMethod;
    if (logoutMethod === "GET") {
      window.location.replace(kc.createLogoutUrl(options));
      return;
    }
    // POST logout
    const form: HTMLFormElement = document.createElement("form");
    form.setAttribute("method", "POST");
    form.setAttribute("action", kc.createLogoutUrl(options));
    form.style.display = "none";

    const data: Record<string, string | undefined> = {
      id_token_hint: kc.idToken,
      client_id: kc.clientId,
      post_logout_redirect_uri: kc.adapter.redirectUri(options),
    };

    for (const [name, value] of Object.entries(data)) { // Replaced forEach with for...of
      if (value) {
        const input: HTMLInputElement = document.createElement("input");
        input.setAttribute("type", "hidden");
        input.setAttribute("name", name);
        input.setAttribute("value", value);
        form.appendChild(input);
      }
    }

    document.body.appendChild(form);
    form.submit();
  },
  register: async (options?: IKeycloakRegisterOptions): Promise<void> => {
    window.location.assign(await kc.createRegisterUrl(options));
  },
  accountManagement: (): void => {
    const accountUrl: string | undefined = kc.createAccountUrl();
    if (accountUrl) {
      window.location.href = accountUrl;
    } else {
      throw new Error(
        "Account management not supported by the OIDC server, or realm URL not configured.",
      );
    }
  },
  redirectUri: (options?: { redirectUri?: string }): string => {
    return options?.redirectUri ?? kc.redirectUri ?? location.href;
  },
});

// --- KEYCLOAK MAIN CLASS ---
interface IPromiseBox<T = boolean> {
  setSuccess: (value: T | PromiseLike<T>) => void;
  setError: (reason?: unknown) => void;
}

interface ILoginIFrameOptions {
  enable: boolean;
  callbackList: Array<IPromiseBox<boolean>>;
  interval: number;
  iframe?: HTMLIFrameElement;
  iframeOrigin?: string;
}

type ParsedToken = Record<string, unknown>; // Consider defining more specific types based on token claims

export class Keycloak {
  public clientId!: string;
  public realm!: string;
  public authServerUrl?: string;

  public authenticated: boolean = false;
  public didInitialize: boolean = false;
  public loginRequired: boolean = false;
  public profile?: IKeycloakProfile;
  public userInfo?: ParsedToken;
  public token?: string;
  public refreshToken?: string;
  public idToken?: string;
  public tokenParsed?: ParsedToken;
  public refreshTokenParsed?: ParsedToken;
  public idTokenParsed?: ParsedToken;
  public sessionId?: string;
  public subject?: string;
  public realmAccess?: { roles: string[] };
  public resourceAccess?: Record<string, { roles: string[] }>;
  public timeSkew?: number;

  public flow: KeycloakFlow = "standard";
  public responseMode: KeycloakResponseMode = "fragment";
  public responseType: KeycloakResponseType = "code";
  public pkceMethod: KeycloakPkceMethod | false = "S256";
  public scope?: string;
  public enableLogging: boolean = false;
  public silentCheckSsoRedirectUri?: string;
  public silentCheckSsoFallback: boolean = true;
  public redirectUri?: string;
  public logoutMethod: KeycloakLogoutMethod = "GET";
  public messageReceiveTimeout: number = 10000;

  public endpoints!: IEndpoints;
  public adapter!: IKeycloakAdapter;

  public onReady?: (authenticated: boolean) => void;
  public onAuthSuccess?: () => void;
  public onAuthError?: (errorDetail?: unknown) => void;
  public onActionUpdate?: (status: string, action: string) => void;
  public onAuthRefreshSuccess?: () => void;
  public onAuthRefreshError?: () => void;
  public onAuthLogout?: () => void;
  public onTokenExpired?: () => void;

  readonly #config: IKeycloakConfig | string;
  #loginIframe: ILoginIFrameOptions = {
    enable: true,
    callbackList: [],
    interval: 5,
  };
  #useNonce: boolean = true;
  readonly #callbackStorage: ICallbackStorage = createCallbackStorage();
  public tokenTimeoutHandle?: number;
  #refreshQueue: Array<IPromiseBox<boolean>> = [];

  constructor(config: IKeycloakConfig | string) {
    this.#config = config;

    if (!(this instanceof Keycloak)) {
      throw new Error("Keycloak constructor must be called with 'new'");
    }

    if (typeof this.#config === "string") {
      if (!this.#config.trim()) {
        throw new Error("Config URL string cannot be empty");
      }
    } else if (isObject<IKeycloakConfig>(this.#config)) {
      const requiredProperties: Array<keyof IKeycloakConfig> =
        "oidcProvider" in this.#config
          ? ["clientId"]
          : ["url", "realm", "clientId"];

      for (const property of requiredProperties) { // Replaced forEach
        if (!this.#config[property]) {
          throw new Error(`Missing required config property '${property}'`);
        }
      }
    } else {
      throw new Error("Config must be an object or a non-empty URL string");
    }

    if (typeof window !== "undefined" && !globalThis.isSecureContext) {
      createLogger(console.warn)(
        "[KEYCLOAK] This application is not running in a secure context (HTTPS or localhost). Keycloak JS may not work as expected. See: https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts",
      );
    }
  }

  public init = async (
    initOptions: IKeycloakInitOptions = {},
  ): Promise<boolean> => {
    if (this.didInitialize) {
      throw new Error("Keycloak instance already initialized");
    }
    this.didInitialize = true;
    this.authenticated = false;

    this.adapter = defaultAdapter(this);

    if (typeof initOptions.useNonce === "boolean") {
      this.#useNonce = initOptions.useNonce;
    }
    if (typeof initOptions.checkLoginIframe === "boolean") {
      this.#loginIframe.enable = initOptions.checkLoginIframe;
    }
    if (typeof initOptions.checkLoginIframeInterval === "number") {
      this.#loginIframe.interval = initOptions.checkLoginIframeInterval;
    }
    if (initOptions.onLoad === "login-required") {
      this.loginRequired = true;
    }
    if (initOptions.responseMode) {
      this.responseMode = initOptions.responseMode;
    }

    if (initOptions.flow) {
      this.flow = initOptions.flow;
      switch (this.flow) {
        case "standard":
          this.responseType = "code";
          break;
        case "implicit":
          this.responseType = "id_token token";
          break;
        case "hybrid":
          this.responseType = "code id_token token";
          break;
        default:
          throw new Error(
            `Invalid flow value: ${this.flow}. Must be one of 'standard', 'implicit', or 'hybrid'.`,
          );
      }
    } else {
      this.flow = "standard";
      this.responseType = "code";
    }

    if (typeof initOptions.timeSkew === "number") {
      this.timeSkew = initOptions.timeSkew;
    }
    if (initOptions.redirectUri) {
      this.redirectUri = initOptions.redirectUri;
    }
    if (initOptions.silentCheckSsoRedirectUri) {
      this.silentCheckSsoRedirectUri = initOptions.silentCheckSsoRedirectUri;
    }
    if (typeof initOptions.silentCheckSsoFallback === "boolean") {
      this.silentCheckSsoFallback = initOptions.silentCheckSsoFallback;
    }
    if (initOptions.pkceMethod) { // pkceMethod can be false
      this.pkceMethod = initOptions.pkceMethod;
    }
    if (typeof initOptions.enableLogging === "boolean") {
      this.enableLogging = initOptions.enableLogging;
      (globalThis as { enableLogging?: boolean }).enableLogging =
        this.enableLogging;
    }
    if (initOptions.logoutMethod) {
      this.logoutMethod = initOptions.logoutMethod;
    }
    if (typeof initOptions.scope === "string") {
      this.scope = initOptions.scope;
    }
    if (
      typeof initOptions.messageReceiveTimeout === "number" &&
      initOptions.messageReceiveTimeout > 0
    ) {
      this.messageReceiveTimeout = initOptions.messageReceiveTimeout;
    }

    // This promise construction is a bit complex due to async operations inside the new Promise constructor.
    // It's generally better to await async operations and then construct the promise if needed,
    // or use the async function's implicit promise.
    // For now, keeping structure but ensuring types.
    let initPromiseResolve!: (value: boolean | PromiseLike<boolean>) => void;
    let initPromiseReject!: (reason?: unknown) => void;
    
    const initInternalPromise = new Promise<boolean>((resolve, reject) => {
      initPromiseResolve = resolve;
      initPromiseReject = reject;
    });

    const initialAuthProcessing = async (): Promise<void> => {
      // Type for callback should be more specific if possible.
      // Assuming parseCallback returns a flat Record<string, string> for now.
      const callback: Record<string, string> | undefined = this.parseCallback(
        window.location.href,
      );

      if (callback?.valid === "true") { // Check against string "true"
        window.history.replaceState(
          window.history.state,
          "",
          callback.newUrl, // newUrl should be part of callback object
        );
        await this.setupCheckLoginIframe();
        await this.#processCallback(
          callback,
          initPromiseResolve,
          initPromiseReject,
        );
        return;
      }

      if (initOptions.token && initOptions.refreshToken) {
        this.#setToken(
          initOptions.token,
          initOptions.refreshToken,
          initOptions.idToken,
        );

        if (this.#loginIframe.enable) {
          await this.setupCheckLoginIframe();
          try {
            const sessionUnchanged: boolean = await this.checkLoginIframe();
            if (sessionUnchanged) {
              this.onAuthSuccess?.();
              this.scheduleCheckIframe();
              initPromiseResolve(this.authenticated);
            } else {
              initPromiseResolve(this.authenticated);
            }
          } catch (e) {
            createLogger(console.error)(
              "[KEYCLOAK] Error in checkLoginIframe during init with tokens",
              e instanceof Error ? e.message : String(e),
            );
            initPromiseReject(e);
          }
        } else {
          try {
            await this.updateToken(-1);
            this.onAuthSuccess?.();
            initPromiseResolve(this.authenticated);
          } catch (error) {
            this.onAuthError?.(error);
            if (initOptions.onLoad) {
              await this.#handleOnLoad(
                initOptions,
                initPromiseResolve,
                initPromiseReject,
              );
            } else {
              initPromiseReject(error);
            }
          }
        }
        return;
      }

      if (initOptions.onLoad) {
        await this.#handleOnLoad(
          initOptions,
          initPromiseResolve,
          initPromiseReject,
        );
      } else if (this.silentCheckSsoRedirectUri) {
        await this.#checkSsoSilently(initPromiseResolve, initPromiseReject);
      } else {
        initPromiseResolve(this.authenticated);
      }
    };

    try {
      await this.#loadConfig();
      await this.check3pCookiesSupported();
      await initialAuthProcessing(); // This will trigger resolve/reject for initInternalPromise
      this.authenticated = await initInternalPromise; // Wait for the processing to complete
    } catch (error) {
      createLogger(console.error)(
        "[KEYCLOAK] Failed to initialize Keycloak",
        error instanceof Error ? error.message : String(error),
      );
      this.didInitialize = false;
      this.onAuthError?.(error);
      throw error;
    } finally {
      this.onReady?.(this.authenticated);
    }
    return this.authenticated;
  };

  #handleOnLoad = async (
    initOptions: IKeycloakInitOptions,
    resolve: (value: boolean | PromiseLike<boolean>) => void,
    reject: (reason?: unknown) => void,
  ): Promise<void> => {
    try {
      const onLoadAction: KeycloakOnLoad | undefined = initOptions.onLoad;
      if (onLoadAction === "check-sso") {
        if (this.#loginIframe.enable) {
          await this.setupCheckLoginIframe();
          const sessionUnchanged: boolean = await this.checkLoginIframe();
          if (!sessionUnchanged) {
            if (this.silentCheckSsoRedirectUri) {
              await this.#checkSsoSilently(resolve, reject);
            } else {
              resolve(this.authenticated);
            }
          } else {
            resolve(this.authenticated);
          }
        } else {
          if (this.silentCheckSsoRedirectUri) {
            await this.#checkSsoSilently(resolve, reject);
          } else {
            resolve(this.authenticated);
          }
        }
      } else if (onLoadAction === "login-required") {
        await this.login(
          initOptions.locale ? { locale: initOptions.locale } : {},
        );
        resolve(this.authenticated); // Typically, login() redirects, so this might not be hit.
      } else if (onLoadAction) { // Any other string value
        createLogger(console.warn)(
          `[KEYCLOAK] Invalid value for onLoad: ${onLoadAction}`,
        );
        resolve(this.authenticated);
      } else { // onLoad is undefined
        resolve(this.authenticated);
      }
    } catch (error) {
      reject(error);
    }
  };

  #checkSsoSilently = async (
    resolve: (value: boolean | PromiseLike<boolean>) => void,
    reject: (reason?: unknown) => void,
  ): Promise<void> => {
    if (!this.silentCheckSsoRedirectUri) {
      reject(new Error("silentCheckSsoRedirectUri is not configured."));
      return;
    }

    const iframe: HTMLIFrameElement = document.createElement("iframe");
    let messageCallback: ((event: MessageEvent) => void) | undefined;
    let timeoutHandle: number | undefined;

    const cleanup = (): void => {
      if (timeoutHandle) {
        window.clearTimeout(timeoutHandle);
      }
      if (messageCallback) {
        window.removeEventListener("message", messageCallback);
      }
      if (iframe.parentNode) {
        iframe.parentNode.removeChild(iframe);
      }
    };

    try {
      const ssoLoginUrl: string = await this.createLoginUrl({
        prompt: "none",
        redirectUri: this.silentCheckSsoRedirectUri,
      });

      let iframeSrcOrigin: string = "";
      try {
        const parsedUrl: URL = new URL(ssoLoginUrl);
        iframeSrcOrigin = parsedUrl.origin;
      } catch (e) {
        createLogger(console.warn)(
          "[KEYCLOAK] Could not parse silent SSO iframe src to get origin, using current window origin as fallback.",
          e instanceof Error ? e.message : String(e),
        );
        iframeSrcOrigin = window.location.origin;
      }

      iframe.setAttribute("src", ssoLoginUrl);
      iframe.setAttribute(
        "sandbox",
        "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
      );
      iframe.setAttribute("title", "keycloak-silent-check-sso-iframe");
      iframe.style.display = "none";

      messageCallback = (event: MessageEvent): void => {
        if (
          event.origin !== iframeSrcOrigin ||
          iframe.contentWindow !== event.source ||
          typeof event.data !== "string"
        ) {
          return;
        }

        const oauth: Record<string, string> | undefined = this.parseCallback(
          event.data as string,
        );
        cleanup();

        if (oauth?.valid === "true") {
          this.#processCallback(oauth, resolve, reject).catch(reject);
        } else {
          createLogger(console.warn)(
            "[KEYCLOAK] Silent SSO failed:",
            oauth?.error ?? "Invalid or no callback from SSO iframe",
          );
          resolve(this.authenticated);
        }
      };

      window.addEventListener("message", messageCallback);
      document.body.appendChild(iframe);

      timeoutHandle = window.setTimeout(() => {
        cleanup();
        createLogger(console.warn)("[KEYCLOAK] Silent SSO timed out.");
        resolve(this.authenticated);
      }, this.messageReceiveTimeout);
    } catch (error) {
      cleanup();
      createLogger(console.error)(
        "[KEYCLOAK] Error in #checkSsoSilently setup:",
        error instanceof Error ? error.message : String(error),
      );
      reject(error);
    }
  };

  #getRealmUrl = (): string | undefined => {
    if (typeof this.authServerUrl === "string" && this.authServerUrl.trim()) {
      return (
        this.authServerUrl.replace(/\/$/, "") +
        "/realms/" +
        encodeURIComponent(this.realm)
      );
    }
    return undefined;
  };

  #processCallback = async (
    oauth: Record<string, string>,
    resolve: (value: boolean | PromiseLike<boolean>) => void,
    reject: (reason?: unknown) => void,
  ): Promise<void> => {
    const {
      code,
      error,
      prompt,
      kc_action_status,
      kc_action,
      access_token,
      id_token,
      pkceCodeVerifier,
      redirectUri, // This is the decoded one from stored state via parseCallback
    } = oauth;
    // loginOptions is also in oauth if it was stored
    const loginOptionsFromOAuth: IKeycloakLoginOptions | undefined = oauth.loginOptions ? JSON.parse(oauth.loginOptions) as IKeycloakLoginOptions : undefined;


    if (kc_action_status && this.onActionUpdate) {
      this.onActionUpdate(
        kc_action_status as string,
        kc_action as string,
      );
    }

    if (error) {
      if (prompt !== "none") {
        if (oauth.error_description === "authentication_expired") {
          try {
            await this.login(loginOptionsFromOAuth);
            resolve(this.authenticated);
          } catch (loginErr) {
            reject(loginErr);
          }
        } else {
          const errorData: { error: string; error_description?: string } = {
            error: error as string,
            error_description: oauth.error_description as string | undefined,
          };
          this.onAuthError?.(errorData);
          reject(errorData);
        }
      } else {
        resolve(this.authenticated);
      }
      return;
    }

    if (this.flow !== "standard" && (access_token || id_token)) {
      try {
        this.#authSuccess(oauth, access_token, undefined, id_token);
        this.onAuthSuccess?.();
        resolve(this.authenticated);
      } catch (authErr) {
        this.onAuthError?.({
          error: "invalid_nonce",
          error_description: (authErr as Error).message,
        });
        reject(authErr);
      }
      return;
    }

    if (this.flow !== "implicit" && code) {
      try {
        const response: IAccessTokenResponse = await this.#fetchAccessToken(
          this.endpoints.token(),
          code,
          this.clientId,
          redirectUri, // Use the decoded redirectUri
          pkceCodeVerifier,
        );
        this.#authSuccess(
          oauth,
          response.access_token,
          response.refresh_token,
          response.id_token,
        );

        if (this.flow === "standard") {
          this.onAuthSuccess?.();
        }
        this.scheduleCheckIframe();
        resolve(this.authenticated);
      } catch (fetchErr) {
        const isNonceError: boolean = fetchErr instanceof Error && fetchErr.message === 'Invalid nonce.';
        this.onAuthError?.(
          isNonceError
            ? { error: "invalid_nonce", error_description: (fetchErr as Error).message }
            : fetchErr,
        );
        reject(fetchErr);
      }
      return;
    }
    resolve(this.authenticated);
  };

  #authSuccess = (
    oauth: Record<string, string>,
    accessToken?: string,
    refreshToken?: string,
    idToken?: string,
  ): void => {
    const timeLocal: number = Date.now();
    this.#setToken(accessToken, refreshToken, idToken, timeLocal);

    if (
      this.#useNonce &&
      this.idTokenParsed &&
      this.idTokenParsed.nonce !== oauth.storedNonce
    ) {
      createLogger(console.info)("[KEYCLOAK] Invalid nonce, clearing token");
      this.clearToken();
      throw new Error("Invalid nonce.");
    }
  };

  #setToken = (
    token?: string,
    refreshToken?: string,
    idToken?: string,
    timeLocal?: number,
  ): void => {
    if (this.#tokenTimeoutHandle) {
      window.clearTimeout(this.#tokenTimeoutHandle);
      this.#tokenTimeoutHandle = undefined;
    }

    if (refreshToken) {
      this.refreshToken = refreshToken;
      try {
        this.refreshTokenParsed = decodeToken(refreshToken);
      } catch (e) {
        createLogger(console.error)("Failed to parse refresh token", e instanceof Error ? e.message : String(e));
        this.refreshTokenParsed = undefined;
      }
    } else {
      this.refreshToken = undefined;
      this.refreshTokenParsed = undefined;
    }

    if (idToken) {
      this.idToken = idToken;
      try {
        this.idTokenParsed = decodeToken(idToken);
      } catch (e) {
        createLogger(console.error)("Failed to parse ID token", e instanceof Error ? e.message : String(e));
        this.idTokenParsed = undefined;
      }
    } else {
      this.idToken = undefined;
      this.idTokenParsed = undefined;
    }

    if (token) {
      this.token = token;
      try {
        this.tokenParsed = decodeToken(token);
      } catch (e) {
        createLogger(console.error)("Failed to parse access token", e instanceof Error ? e.message : String(e));
        this.tokenParsed = undefined;
      }

      if (this.tokenParsed) {
        this.sessionId = this.tokenParsed.sid as string | undefined;
        this.authenticated = true;
        this.subject = this.tokenParsed.sub as string | undefined;
        this.realmAccess = this.tokenParsed.realm_access as
          | { roles: string[] }
          | undefined;
        this.resourceAccess = this.tokenParsed.resource_access as
          | Record<string, { roles: string[] }>
          | undefined;

        if (timeLocal && typeof this.tokenParsed.iat === "number") {
          this.timeSkew =
            Math.floor(timeLocal / 1000) - this.tokenParsed.iat;
        }

        if (this.onTokenExpired && typeof this.tokenParsed.exp === "number" && typeof this.timeSkew === "number") {
          const expiresInMs: number =
            (this.tokenParsed.exp - (Date.now() / 1000) + this.timeSkew) * 1000;
            
          createLogger(console.info)(
            `[KEYCLOAK] Token expires in ${Math.round(expiresInMs / 1000)} s (timeskew: ${this.timeSkew}s)`,
          );
          if (expiresInMs <= 0) {
            this.onTokenExpired();
          } else {
            this.#tokenTimeoutHandle = window.setTimeout(
              this.onTokenExpired,
              expiresInMs,
            );
          }
        }
      } else {
        this.token = undefined;
        this.sessionId = undefined;
        this.subject = undefined;
        this.realmAccess = undefined;
        this.resourceAccess = undefined;
        this.authenticated = false;
      }
    } else {
      this.token = undefined;
      this.tokenParsed = undefined;
      this.sessionId = undefined;
      this.subject = undefined;
      this.realmAccess = undefined;
      this.resourceAccess = undefined;
      this.authenticated = false;
    }
  };

  #loadConfig = async (): Promise<void> => {
    if (typeof this.#config === "string") {
      const jsonConfig: IJsonConfig = await fetchJSON<IJsonConfig>(
        this.#config,
      );
      this.authServerUrl = jsonConfig["auth-server-url"];
      this.realm = jsonConfig.realm;
      this.clientId = jsonConfig.resource;
      this.endpoints = this.#defaultEndpoints();
    } else if ("oidcProvider" in this.#config && this.#config.oidcProvider) {
      const providerConfigUrl: string | undefined =
        typeof this.#config.oidcProvider === "string"
          ? `${this.#config.oidcProvider.replace(/\/$/, "")}/.well-known/openid-configuration`
          : undefined;

      const oidcMetadata: IOpenIdProviderMetadata = providerConfigUrl
        ? await fetchJSON<IOpenIdProviderMetadata>(providerConfigUrl)
        : (this.#config.oidcProvider as IOpenIdProviderMetadata);

      this.clientId = this.#config.clientId;
      this.endpoints = this.#oidcEndpoints(oidcMetadata);
      if (this.#config.realm) this.realm = this.#config.realm; // Realm might be needed for non-standard OIDC interactions
      // authServerUrl might be derived from issuer in oidcMetadata if needed for other purposes
      if (oidcMetadata.issuer) {
         // Basic derivation, might need adjustment based on issuer format
         const issuerUrl = new URL(oidcMetadata.issuer);
         this.authServerUrl = issuerUrl.origin;
      }

    } else {
      this.authServerUrl = this.#config.url;
      this.realm = this.#config.realm;
      this.clientId = this.#config.clientId;
      this.endpoints = this.#defaultEndpoints();
    }

    if (!this.clientId) {
      throw new Error("Client ID is missing after configuration loading.");
    }
    if (!this.realm && !(typeof this.#config !== 'string' && "oidcProvider" in this.#config)) {
       // Realm is critical for default endpoints, ensure it's set if not in OIDC provider mode
      throw new Error(
        "Realm is missing after configuration loading and is required for default Keycloak setup.",
      );
    }
  };

  #defaultEndpoints = (): IEndpoints => {
    const realmUrl: string | undefined = this.#getRealmUrl();
    if (!realmUrl) {
      throw new Error(
        "Authentication server URL and realm must be configured for default endpoints.",
      );
    }
    return {
      authorize: (): string => `${realmUrl}/protocol/openid-connect/auth`,
      token: (): string => `${realmUrl}/protocol/openid-connect/token`,
      logout: (): string => `${realmUrl}/protocol/openid-connect/logout`,
      checkSessionIframe: (): string =>
        `${realmUrl}/protocol/openid-connect/login-status-iframe.html`,
      thirdPartyCookiesIframe: (): string =>
        `${realmUrl}/protocol/openid-connect/3p-cookies/step1.html`,
      register: (): string =>
        `${realmUrl}/protocol/openid-connect/registrations`,
      userinfo: (): string => `${realmUrl}/protocol/openid-connect/userinfo`,
    };
  };

  #oidcEndpoints = (
    oidcConfig: IOpenIdProviderMetadata,
  ): IEndpoints => ({
    authorize: (): string => oidcConfig.authorization_endpoint,
    token: (): string => oidcConfig.token_endpoint,
    logout: (): string => {
      if (!oidcConfig.end_session_endpoint) {
        throw new Error(
          "OIDC provider metadata does not specify an end_session_endpoint.",
        );
      }
      return oidcConfig.end_session_endpoint;
    },
    checkSessionIframe: (): string => {
      if (!oidcConfig.check_session_iframe) {
        throw new Error(
          "OIDC provider metadata does not specify a check_session_iframe.",
        );
      }
      return oidcConfig.check_session_iframe;
    },
    register: (): string => {
      throw new Error(
        "Registration is not supported via OIDC discovery in this adapter.",
      );
    },
    userinfo: (): string => {
      if (!oidcConfig.userinfo_endpoint) {
        throw new Error(
          "OIDC provider metadata does not specify a userinfo_endpoint.",
        );
      }
      return oidcConfig.userinfo_endpoint;
    },
    thirdPartyCookiesIframe: (): string => {
      throw new Error(
        "Third-party cookie check iframe is not supported in generic OIDC mode.",
      );
    },
  });

  #fetchAccessToken = async (
    url: string,
    code: string,
    clientId: string,
    redirectUri: string,
    pkceCodeVerifier?: string,
  ): Promise<IAccessTokenResponse> => {
    const bodyParams: URLSearchParams = new URLSearchParams();
    bodyParams.append("grant_type", "authorization_code");
    bodyParams.append("code", code);
    bodyParams.append("client_id", clientId);
    bodyParams.append("redirect_uri", redirectUri);

    if (pkceCodeVerifier) {
      bodyParams.append("code_verifier", pkceCodeVerifier);
    }

    return fetchJSON<IAccessTokenResponse>(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: bodyParams,
      credentials: "omit",
    });
  };

  #fetchRefreshToken = async (
    url: string,
    refreshTokenValue: string,
    clientId: string,
  ): Promise<IAccessTokenResponse> => {
    const bodyParams: URLSearchParams = new URLSearchParams();
    bodyParams.append("grant_type", "refresh_token");
    bodyParams.append("refresh_token", refreshTokenValue);
    bodyParams.append("client_id", clientId);

    return fetchJSON<IAccessTokenResponse>(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: bodyParams,
      credentials: "omit",
    });
  };

  public login = async (
    options?: IKeycloakLoginOptions,
  ): Promise<void> => {
    return this.adapter.login(options);
  };

  public logout = async (
    options?: IKeycloakLogoutOptions,
  ): Promise<void> => {
    return this.adapter.logout(options);
  };

  public createLoginUrl = async (
    options?: IKeycloakLoginOptions,
  ): Promise<string> => {
    const state: string = createUUID();
    const nonce: string = createUUID();
    const redirectUriParams: { redirectUri?: string } = {};
    if (options?.redirectUri) {
      redirectUriParams.redirectUri = options.redirectUri;
    } else if (this.redirectUri) { // Use instance redirectUri if options doesn't have one
      redirectUriParams.redirectUri = this.redirectUri;
    }
    const finalRedirectUri: string = this.adapter.redirectUri(redirectUriParams);

    const callbackState: ICallbackState = {
      state,
      nonce,
      redirectUri: encodeURIComponent(finalRedirectUri),
      loginOptions: options,
      prompt: options?.prompt,
    };

    const authUrl: string =
      options?.action === "register"
        ? this.endpoints.register()
        : this.endpoints.authorize();

    let currentScope: string = options?.scope ?? this.scope ?? "openid";
    const scopeValues: string[] = currentScope.split(" ");
    if (!arrayHas(scopeValues, "openid")) {
      scopeValues.unshift("openid");
    }
    currentScope = scopeValues.join(" ");

    const params: URLSearchParams = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: finalRedirectUri,
      state,
      response_mode: this.responseMode,
      response_type: this.responseType,
      scope: currentScope,
    });

    if (this.#useNonce) {
      params.append("nonce", nonce);
    }
    if (options?.prompt) {
      params.append("prompt", options.prompt);
    }
    if (typeof options?.maxAge === "number") {
      params.append("max_age", String(options.maxAge));
    }
    if (options?.loginHint) {
      params.append("login_hint", options.loginHint);
    }
    if (options?.idpHint) {
      params.append("kc_idp_hint", options.idpHint);
    }
    if (options?.action && options.action !== "register") {
      params.append("kc_action", options.action);
    }
    if (options?.locale) {
      params.append("ui_locales", options.locale);
    }

    if (this.pkceMethod) { // pkceMethod can be false
      const codeVerifier: string = generateCodeVerifier(96);
      const pkceChallenge: string = await generatePkceChallenge(
        this.pkceMethod,
        codeVerifier,
      );
      callbackState.pkceCodeVerifier = codeVerifier;
      params.append("code_challenge", pkceChallenge);
      params.append("code_challenge_method", this.pkceMethod);
    }

    this.#callbackStorage.add(callbackState);
    return `${authUrl}?${params.toString()}`;
  };

  public createLogoutUrl = (
    options?: IKeycloakLogoutOptions,
  ): string => {
    const logoutMethodToUse: KeycloakLogoutMethod =
      options?.logoutMethod ?? this.logoutMethod;
    const logoutUrl: string = this.endpoints.logout();

    if (logoutMethodToUse === "POST") {
      return logoutUrl;
    }

    const params: URLSearchParams = new URLSearchParams();
    // OIDC RP-Initiated Logout spec recommends id_token_hint.
    // Some providers might also want client_id or post_logout_redirect_uri.
    if (this.idToken) {
       params.append("id_token_hint", this.idToken);
       const postLogoutRedirectUri: string = this.adapter.redirectUri(options);
       if (postLogoutRedirectUri) { // Only add if a redirect URI is actually configured/provided
         params.append("post_logout_redirect_uri", postLogoutRedirectUri);
       }
    } else if (options?.redirectUri) {
        // Fallback if no idToken but redirectUri is in options (less common for OIDC spec compliance)
        const postLogoutRedirectUri: string = this.adapter.redirectUri(options);
        if (postLogoutRedirectUri) {
           params.append("post_logout_redirect_uri", postLogoutRedirectUri);
        }
    }
    // client_id can sometimes be required by providers, even for GET logout
    if (this.clientId) {
        params.append("client_id", this.clientId);
    }

    const queryString = params.toString();
    return queryString ? `${logoutUrl}?${queryString}` : logoutUrl;
  };

  public createRegisterUrl = async (
    options?: IKeycloakRegisterOptions,
  ): Promise<string> => {
    return this.createLoginUrl({ ...options, action: "register" });
  };

  public createAccountUrl = (
    options?: IKeycloakAccountOptions,
  ): string | undefined => {
    const realmUrl: string | undefined = this.#getRealmUrl();
    if (!realmUrl) {
      createLogger(console.warn)(
        "[KEYCLOAK] Cannot create account URL if authServerUrl and realm are not configured.",
      );
      return undefined;
    }
    const params: URLSearchParams = new URLSearchParams({
      referrer: this.clientId,
      referrer_uri: this.adapter.redirectUri(options),
    });
    return `${realmUrl}/account?${params.toString()}`;
  };

  public accountManagement = async (): Promise<void> => {
    return this.adapter.accountManagement();
  };

  public hasRealmRole = (role: string): boolean => {
    return !!this.realmAccess?.roles?.includes(role);
  };

  public hasResourceRole = (
    role: string,
    resource?: string,
  ): boolean => {
    const targetResource: string = resource ?? this.clientId;
    return !!this.resourceAccess?.[targetResource]?.roles?.includes(role);
  };

  public loadUserProfile = async (): Promise<IKeycloakProfile> => {
    if (!this.token) {
      throw new Error("User not authenticated, cannot load profile.");
    }
    const realmUrl: string | undefined = this.#getRealmUrl();
    if (!realmUrl) {
      throw new Error(
        "Cannot load user profile; authServerUrl and realm not configured.",
      );
    }
    const profileUrl: string = `${realmUrl}/account`; // Keycloak specific endpoint
    try {
      const profile: IKeycloakProfile = await fetchJSON<IKeycloakProfile>(
        profileUrl,
        {
          headers: [buildAuthorizationHeader(this.token)],
        },
      );
      this.profile = profile;
      return profile;
    } catch (error) {
      createLogger(console.error)(
        "[KEYCLOAK] Failed to load user profile:",
        error instanceof Error ? error.message : String(error),
      );
      throw new Error(
        `Failed to load user profile: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };

  public loadUserInfo = async (): Promise<ParsedToken> => {
    if (!this.token) {
      throw new Error("User not authenticated, cannot load user info.");
    }
    const userInfoUrl: string = this.endpoints.userinfo();
    try {
      const userInfo: ParsedToken = await fetchJSON<ParsedToken>(userInfoUrl, {
        headers: [buildAuthorizationHeader(this.token)],
      });
      this.userInfo = userInfo;
      return userInfo;
    } catch (error) {
      createLogger(console.error)(
        "[KEYCLOAK] Failed to load user info:",
        error instanceof Error ? error.message : String(error),
      );
      throw new Error(
        `Failed to load user info: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  };

  public isTokenExpired = (minValiditySeconds: number = 0): boolean => {
    if (!this.tokenParsed) {
      // If no token is parsed, we can't determine its expiration.
      // Depending on strictness, could throw or return true.
      // Returning true (expired) is safer if called without checking authentication.
      return true;
    }
    if (typeof this.timeSkew !== "number") {
      createLogger(console.warn)(
        "[KEYCLOAK] Cannot reliably check token expiration without timeSkew. Assuming token is expired.",
      );
      return true;
    }
    if (typeof this.tokenParsed.exp !== "number") {
      createLogger(console.warn)(
        "[KEYCLOAK] Token 'exp' claim is missing or not a number. Assuming token is expired.",
      );
      return true;
    }

    const currentUnixTime: number = Math.ceil(Date.now() / 1000);
    // Time remaining = (expiration time + time skew) - current time
    const timeRemaining: number =
      this.tokenParsed.exp + this.timeSkew - currentUnixTime;

    return timeRemaining < minValiditySeconds;
  };

  public updateToken = async (
    minValiditySeconds: number = 5,
  ): Promise<boolean> => {
    if (!this.refreshToken) {
      createLogger(console.warn)("[KEYCLOAK] No refresh token available to update token.");
      return false;
    }

    const needsRefresh: boolean =
      minValiditySeconds === -1 || // Force refresh
      !this.tokenParsed || // No current access token
      this.isTokenExpired(minValiditySeconds);

    if (!needsRefresh) {
      return false;
    }

    let resolvePromise!: (value: boolean | PromiseLike<boolean>) => void;
    let rejectPromise!: (reason?: unknown) => void;
    const promise = new Promise<boolean>((resolve, reject) => {
      resolvePromise = resolve;
      rejectPromise = reject;
    });
    this.#refreshQueue.push({
      setSuccess: resolvePromise,
      setError: rejectPromise,
    });

    if (this.#refreshQueue.length === 1) {
      try {
        const tokenUrl: string = this.endpoints.token();
        const refreshedTokens: IAccessTokenResponse =
          await this.#fetchRefreshToken(
            tokenUrl,
            this.refreshToken,
            this.clientId,
          );

        const timeLocal: number = Date.now();
        this.#setToken(
          refreshedTokens.access_token,
          refreshedTokens.refresh_token,
          refreshedTokens.id_token,
          timeLocal,
        );

        this.onAuthRefreshSuccess?.();
        this.#refreshQueue.forEach((p) => p.setSuccess(true));
        this.#refreshQueue = [];
        return true; // For the initial caller
      } catch (error) {
        createLogger(console.error)(
          "[KEYCLOAK] Failed to refresh token:",
          error instanceof Error ? error.message : String(error),
        );
        this.onAuthRefreshError?.();
        this.#refreshQueue.forEach((p) => p.setError(error));
        this.#refreshQueue = [];
        throw error; // Rethrow for the initial caller
      }
    }
    return promise; // For subsequent callers in the queue
  };

  public clearToken = (): void => {
    if (this.token) {
      this.#setToken(undefined, undefined, undefined, undefined);
      this.onAuthLogout?.();
      if (this.loginRequired) {
        this.login().catch((error) => {
          createLogger(console.error)(
            "[KEYCLOAK] Auto-login after token clear failed:",
            error instanceof Error ? error.message : String(error),
          );
        });
      }
    }
  };

  public setupCheckLoginIframe = async (): Promise<void> => {
    if (!this.#loginIframe.enable || this.#loginIframe.iframe) {
      return;
    }

    const iframeElement: HTMLIFrameElement = document.createElement("iframe");
    this.#loginIframe.iframe = iframeElement;

    // Wrap in a promise to handle async nature of onload/onerror
    return new Promise<void>((resolve, reject) => {
      iframeElement.onload = (): void => {
        try {
          const authUrl: string = this.endpoints.authorize();
          this.#loginIframe.iframeOrigin = authUrl.startsWith("/")
            ? window.location.origin
            : new URL(authUrl).origin;
          resolve();
        } catch (e) {
          reject(
            new Error(
              `Failed to determine login iframe origin: ${e instanceof Error ? e.message : String(e)}`,
            ),
          );
        }
      };
      iframeElement.onerror = (): void => { // Handle iframe load errors
        reject(new Error("Failed to load login status iframe."));
      };

      iframeElement.setAttribute("src", this.endpoints.checkSessionIframe());
      iframeElement.setAttribute(
        "sandbox",
        "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
      );
      iframeElement.setAttribute("title", "keycloak-session-status-iframe");
      iframeElement.style.display = "none";
      document.body.appendChild(iframeElement);

      // Add event listener after appending, ensuring it's ready.
      // Consider if this should be added only after onload.
      window.addEventListener("message", this.#handleLoginIframeMessage);
    });
  };

  // Extracted message handler for clarity and to be a bound method or correctly referenced.
  #handleLoginIframeMessage = (event: MessageEvent<string>): void => {
    if (
      !this.#loginIframe.iframe ||
      event.origin !== this.#loginIframe.iframeOrigin ||
      this.#loginIframe.iframe.contentWindow !== event.source ||
      !["unchanged", "changed", "error"].includes(event.data)
    ) {
      return;
    }

    if (event.data !== "unchanged") {
      this.clearToken();
    }

    const callbacks: Array<IPromiseBox<boolean>> = [
      ...this.#loginIframe.callbackList,
    ];
    this.#loginIframe.callbackList = [];

    for (const cb of callbacks) { // Replaced forEach
      if (event.data === "error") {
        cb.setError(new Error("Login status iframe reported an error."));
      } else {
        cb.setSuccess(event.data === "unchanged");
      }
    }
  };

  public scheduleCheckIframe = (): void => {
    if (!this.#loginIframe.enable || !this.token) {
      return;
    }
    window.setTimeout(async () => {
      try {
        const sessionUnchanged: boolean = await this.checkLoginIframe();
        if (sessionUnchanged) {
          this.scheduleCheckIframe();
        }
      } catch (error) {
        createLogger(console.warn)(
          "[KEYCLOAK] Failed to check login iframe, will not reschedule.",
          error instanceof Error ? error.message : String(error),
        );
      }
    }, this.#loginIframe.interval * 1000);
  };

  public checkLoginIframe = async (): Promise<boolean> => {
    if (
      !this.#loginIframe.iframe ||
      !this.#loginIframe.iframe.contentWindow ||
      !this.#loginIframe.iframeOrigin
    ) {
      return true; // Cannot check, assume unchanged
    }

    const message: string = `${this.clientId} ${this.sessionId ?? ""}`;
    let resolvePromise!: (value: boolean | PromiseLike<boolean>) => void;
    let rejectPromise!: (reason?: unknown) => void;

    const promise = new Promise<boolean>((resolve, reject) => {
      resolvePromise = resolve;
      rejectPromise = reject;
    });

    this.#loginIframe.callbackList.push({
      setSuccess: resolvePromise,
      setError: rejectPromise,
    });

    if (this.#loginIframe.callbackList.length === 1) {
      this.#loginIframe.iframe.contentWindow.postMessage(
        message,
        this.#loginIframe.iframeOrigin,
      );
    }
    return promise;
  };

  public check3pCookiesSupported = async (): Promise<void> => {
    if (
      !(this.#loginIframe.enable || this.silentCheckSsoRedirectUri) ||
      typeof this.endpoints.thirdPartyCookiesIframe !== "function"
    ) {
      return;
    }

    const iframe: HTMLIFrameElement = document.createElement("iframe");
    let messageListener: ((event: MessageEvent<string>) => void) | undefined; // Typed event.data

    return new Promise<void>((resolve, reject) => {
      try {
        iframe.setAttribute("src", this.endpoints.thirdPartyCookiesIframe());
      } catch (e) { // Catch error if endpoints.thirdPartyCookiesIframe throws (e.g. OIDC mode)
         createLogger(console.warn)("Third-party cookie check iframe endpoint not available.", e instanceof Error ? e.message : String(e));
         resolve(); // Resolve gracefully, as the check cannot be performed.
         return;
      }
      iframe.setAttribute(
        "sandbox",
        "allow-storage-access-by-user-activation allow-scripts allow-same-origin",
      );
      iframe.setAttribute("title", "keycloak-3p-cookie-check-iframe");
      iframe.style.display = "none";

      messageListener = (event: MessageEvent<string>): void => {
        if (
          iframe.contentWindow !== event.source ||
          !["supported", "unsupported"].includes(event.data)
        ) {
          return;
        }

        if (event.data === "unsupported") {
          createLogger(console.warn)(
            "[KEYCLOAK] Third-party cookies are blocked by the browser. Silent authentication and session status checking via iframe may not work.",
          );
          this.#loginIframe.enable = false;
          if (this.silentCheckSsoFallback) {
            this.silentCheckSsoRedirectUri = undefined;
          }
        }
        // Cleanup
        if (messageListener) { // Check if listener exists before removing
          window.removeEventListener("message", messageListener);
          messageListener = undefined; // Clear the reference
        }
        if (iframe.parentNode) {
          iframe.parentNode.removeChild(iframe);
        }
        resolve();
      };
      
      iframe.onerror = (): void => { // Handle iframe load errors
        if (messageListener) window.removeEventListener("message", messageListener);
        if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
        // Resolve rather than reject, as this is a feature detection, not a critical failure
        createLogger(console.warn)("Failed to load 3p cookie check iframe.");
        resolve(); 
      };

      window.addEventListener("message", messageListener);
      document.body.appendChild(iframe);
      
      window.setTimeout(() => {
        if (messageListener) { // If still not resolved/cleaned up
          createLogger(console.warn)("[KEYCLOAK] 3p cookie check timed out.");
          window.removeEventListener("message", messageListener);
          if (iframe.parentNode) {
            iframe.parentNode.removeChild(iframe);
          }
          resolve(); 
        }
      }, this.messageReceiveTimeout);
    });
  };

  public parseCallback = (
    url: string,
  ): Record<string, string> | undefined => {
    const oauthParamsFromUrl: Record<string, string> | undefined =
      this.parseCallbackUrl(url);

    if (!oauthParamsFromUrl?.state) {
      return undefined;
    }

    const storedState: ICallbackState | undefined = this.#callbackStorage.get(
      oauthParamsFromUrl.state,
    );

    if (storedState) {
      const mergedParams: Record<string, string> = {
        ...Object.fromEntries(
          Object.entries(storedState)
          .filter(([, value]) => typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') // Filter out complex objects before string conversion
          .map(([k, v]) => [k, String(v)]) 
        ),
        ...oauthParamsFromUrl,
        valid: "true",
      };
      mergedParams.redirectUri = decodeURIComponent(storedState.redirectUri); // Ensure this is the decoded one
      // loginOptions is an object, so stringify it if it exists to fit Record<string, string>
      if (storedState.loginOptions) {
        mergedParams.loginOptions = JSON.stringify(storedState.loginOptions);
      }
       if (storedState.pkceCodeVerifier) {
        mergedParams.pkceCodeVerifier = storedState.pkceCodeVerifier;
      }
      if (storedState.nonce) {
        mergedParams.storedNonce = storedState.nonce;
      }
      if (storedState.prompt) {
        mergedParams.prompt = storedState.prompt;
      }

      return mergedParams;
    }
    return undefined;
  };

  public parseCallbackUrl = (
    fullUrl: string,
  ): Record<string, string> | undefined => {
    const supportedParamsSet: Set<string> = new Set([
      "state", "session_state", "iss", "error", "error_description", "error_uri",
      "kc_action_status", "kc_action",
      ...(this.flow === "standard" || this.flow === "hybrid" ? ["code"] : []),
      ...(this.flow === "implicit" || this.flow === "hybrid"
        ? ["access_token", "token_type", "id_token", "expires_in"]
        : []),
    ]);

    let paramsStr: string = "";
    let newUrlWithoutCallbackParams: string = fullUrl;

    if (this.responseMode === "query") {
      const queryIdx: number = fullUrl.indexOf("?");
      if (queryIdx !== -1) {
        paramsStr = fullUrl.substring(queryIdx + 1);
        newUrlWithoutCallbackParams = fullUrl.substring(0, queryIdx);
        const fragmentIdx: number = paramsStr.indexOf("#");
        if (fragmentIdx !== -1) {
          newUrlWithoutCallbackParams += paramsStr.substring(fragmentIdx);
          paramsStr = paramsStr.substring(0, fragmentIdx);
        }
      }
    } else if (this.responseMode === "fragment") {
      const fragmentIdx: number = fullUrl.indexOf("#");
      if (fragmentIdx !== -1) {
        paramsStr = fullUrl.substring(fragmentIdx + 1);
        newUrlWithoutCallbackParams = fullUrl.substring(0, fragmentIdx);
      }
    }

    if (!paramsStr) return undefined;

    const parsedResult = this.parseCallbackParams(paramsStr, supportedParamsSet);
    const oauthParams: Record<string, string> = parsedResult.oauthParams;

    if (Object.keys(oauthParams).length === 0 && !parsedResult.remainingParamsString) {
        // If no known OAuth params were found and no other params exist, it's not a valid callback URL for us.
        return undefined;
    }
    
    oauthParams.newUrl = newUrlWithoutCallbackParams + 
                         (parsedResult.remainingParamsString 
                            ? (this.responseMode === 'query' ? '?' : '#') + parsedResult.remainingParamsString 
                            : '');


    // Validate essential params for the flow
    const hasState = !!oauthParams.state;
    if (!hasState) return undefined; // State is mandatory for all flows here

    if (this.flow === "standard" || this.flow === "hybrid") {
      if (oauthParams.code || oauthParams.error) return oauthParams;
    }
    if (this.flow === "implicit" || this.flow === "hybrid") {
      if (oauthParams.access_token || oauthParams.id_token || oauthParams.error) return oauthParams;
    }
    
    // If it's a hybrid flow and only one part of the response is present (e.g. only code, no tokens in fragment yet)
    // it might still be considered valid at this stage, further processing in #processCallback will handle it.
    if (this.flow === "hybrid" && (oauthParams.code || oauthParams.access_token || oauthParams.id_token || oauthParams.error)) {
        return oauthParams;
    }


    return undefined; 
  };

  public parseCallbackParams = (
    paramsString: string,
    knownParams: Set<string>, // Use Set for efficient lookup
  ): {
    oauthParams: Record<string, string>;
    remainingParamsString: string;
  } => {
    const oauthParams: Record<string, string> = {};
    const remainingParamsArray: string[] = [];

    paramsString.split("&").forEach((paramPair: string) => {
      const eqIdx: number = paramPair.indexOf("=");
      const key: string = decodeURIComponent(eqIdx === -1 ? paramPair : paramPair.substring(0, eqIdx));
      const value: string = eqIdx === -1 ? "" : decodeURIComponent(paramPair.substring(eqIdx + 1));

      if (knownParams.has(key)) {
        oauthParams[key] = value;
      } else {
        // Preserve the original encoding for remaining params if needed, though typically not an issue.
        remainingParamsArray.push(paramPair); 
      }
    });

    return {
      oauthParams,
      remainingParamsString: remainingParamsArray.join("&"),
    };
  };
}

export default Keycloak;
