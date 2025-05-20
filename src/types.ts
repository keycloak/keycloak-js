// types.ts
export type KeycloakOnLoad = "login-required" | "check-sso";
export type KeycloakResponseMode = "query" | "fragment";
export type KeycloakResponseType =
  | "code"
  | "id_token token"
  | "code id_token token";
export type KeycloakFlow = "standard" | "implicit" | "hybrid";
export type KeycloakPkceMethod = "S256" | false;

export interface IAcr {
  values: string[];
  essential: boolean;
}

export interface IKeycloakConfig extends Record<string, unknown> {
  url: string;
  realm: string;
  clientId: string;
}

export interface IKeycloakInitOptions {
  useNonce?: boolean;
  adapter?: "default" | "cordova" | "cordova-native" | IKeycloakAdapter;
  onLoad?: KeycloakOnLoad;
  token?: string;
  refreshToken?: string;
  idToken?: string;
  timeSkew?: number;
  checkLoginIframe?: boolean;
  checkLoginIframeInterval?: number;
  responseMode?: KeycloakResponseMode;
  redirectUri?: string;
  silentCheckSsoRedirectUri?: string;
  silentCheckSsoFallback?: boolean;
  flow?: KeycloakFlow;
  pkceMethod?: KeycloakPkceMethod;
  enableLogging?: boolean;
  scope?: string;
  messageReceiveTimeout?: number;
  locale?: string;
  logoutMethod?: "GET" | "POST";
}

export interface INetworkErrorOptions extends ErrorOptions {
  response: Response;
}

export interface IKeycloakLoginOptions {
  scope?: string;
  redirectUri?: string;
  prompt?: "none" | "login" | "consent";
  action?: string;
  maxAge?: number;
  loginHint?: string;
  acr?: IAcr;
  acrValues?: string;
  idpHint?: string;
  locale?: string;
  cordovaOptions?: Record<string, string>;
}

export interface IKeycloakLogoutOptions {
  redirectUri?: string;
  logoutMethod?: "GET" | "POST";
}

export interface IKeycloakRegisterOptions
  extends Omit<IKeycloakLoginOptions, "action"> {}

export interface IKeycloakAccountOptions {
  redirectUri?: string;
}

export interface IKeycloakError {
  error: string;
  error_description: string;
}

export interface IKeycloakAdapter {
  login(options?: IKeycloakLoginOptions): Promise<void>;
  logout(options?: IKeycloakLogoutOptions): Promise<void>;
  register(options?: IKeycloakRegisterOptions): Promise<void>;
  accountManagement(): Promise<void>;
  redirectUri(options?: { redirectUri?: string }, encodeHash?: boolean): string;
}

export interface IKeycloakProfile {
  id?: string;
  username?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled?: boolean;
  emailVerified?: boolean;
  totp?: boolean;
  createdTimestamp?: number;
  attributes?: Record<string, unknown>;
}

export interface IKeycloakRoles {
  roles: string[];
}

export interface IKeycloakResourceAccess {
  [key: string]: IKeycloakRoles;
}

export interface IKeycloakTokenParsed {
  iss?: string;
  sub?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string;
  azp?: string;
  session_state?: string;
  realm_access?: IKeycloakRoles;
  resource_access?: IKeycloakResourceAccess;
  [key: string]: unknown;
}
