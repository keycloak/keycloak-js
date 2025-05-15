/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Helper types and interfaces
export interface IKeycloakTokenParsed {
	exp?: number;
	iat?: number;
	nonce?: string;
	sub?: string;
	sid?: string;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	[key: string]: unknown; // Allow other claims
}

export interface IKeycloakProfile {
	id?: string;
	username?: string;
	email?: string;
	firstName?: string;
	lastName?: string;
	enabled?: boolean;
	emailVerified?: boolean;
	attributes?: Record<string, unknown>;
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	[key: string]: unknown; // Allow other attributes
}

export interface IKeycloakRoles {
	roles: string[];
	[key: string]: unknown;
}

export interface IKeycloakResourceAccess {
	[key: string]: IKeycloakRoles;
}


// Configuration interfaces
export interface IKeycloakConfig {
	url?: string; // e.g. http://localhost:8080
	realm: string;
	clientId: string;
	oidcProvider?: string | IOpenIdProviderMetadata; // URL to OIDC provider or the metadata itself
	'auth-server-url'?: string; // Deprecated, use url instead
	resource?: string; // Deprecated, use clientId instead
}

export type KeycloakConfig = string | IKeycloakConfig; // string is a URL to a json config file

export interface IKeycloakInitOptions {
	useNonce?: boolean;
	adapter?: 'default' | 'cordova' | 'cordova-native' | IKeycloakAdapter;
	onLoad?: 'login-required' | 'check-sso';
	token?: string;
	refreshToken?: string;
	idToken?: string;
	timeSkew?: number;
	responseMode?: 'query' | 'fragment';
	flow?: 'standard' | 'implicit' | 'hybrid';
	checkLoginIframe?: boolean;
	checkLoginIframeInterval?: number;
	redirectUri?: string;
	silentCheckSsoRedirectUri?: string;
	silentCheckSsoFallback?: boolean;
	pkceMethod?: 'S256' | false;
	enableLogging?: boolean;
	scope?: string;
	messageReceiveTimeout?: number;
	locale?: string;
	logoutMethod?: 'POST' | 'GET';
}

// Adapter interface
export interface ILoginOptions {
	prompt?: 'none' | 'login';
	action?: 'register';
	redirectUri?: string;
	locale?: string;
	scope?: string;
	maxAge?: number;
	loginHint?: string;
	idpHint?: string;
	acr?: string; // acr_values in OIDC
	acrValues?: string; // Specific Keycloak extension
	cordovaOptions?: { [key: string]: string };
}

export interface ILogoutOptions {
	redirectUri?: string;
	logoutMethod?: 'POST' | 'GET';
}

export interface IRegisterOptions extends ILoginOptions {
	// Register options are typically a subset of login options
}

export interface IAccountOptions {
	redirectUri?: string;
}

export interface IKeycloakAdapter {
	login(options?: ILoginOptions): Promise<void>;
	logout(options?: ILogoutOptions): Promise<void>;
	register(options?: IRegisterOptions): Promise<void>;
	accountManagement(): Promise<void>;
	redirectUri(options: { redirectUri?: string } | undefined): string;
}


// Callback Storage interface
interface ICallbackStorageState {
	state: string;
	nonce: string;
	redirectUri: string;
	loginOptions?: ILoginOptions;
	prompt?: string;
	pkceCodeVerifier?: string;
	expires?: number; // Expiry timestamp in ms
}

export interface ICallbackStorage {
	get(state: string): ICallbackStorageState | undefined;
	add(state: ICallbackStorageState): void;
	removeItem?(key: string): void; // Optional, only for cookie storage for now
}

// Event handler types
export type KeycloakOnReady = (authenticated?: boolean) => void;
export type KeycloakOnAuthSuccess = () => void;
export interface IKeycloakError {
	error: string;
	error_description?: string;
	[key: string]: unknown;
}
export type KeycloakOnAuthError = (errorData: IKeycloakError) => void;
export type KeycloakOnAuthRefreshSuccess = () => void;
export type KeycloakOnAuthRefreshError = () => void;
export type KeycloakOnAuthLogout = () => void;
export type KeycloakOnTokenExpired = () => void;
export type KeycloakOnActionUpdate = (status: 'success' | 'cancelled' | 'error', action?: string) => void;


const CONTENT_TYPE_JSON = 'application/json';
const STORAGE_KEY_PREFIX = 'kc-callback-';


// Utility Functions (Typed and using const/arrow functions)

const isObject = (input: unknown): input is object => {
	return typeof input === 'object' && input !== null;
};

const bytesToBase64 = (bytes: Uint8Array): string => {
	const binString = String.fromCodePoint(...bytes);
	return btoa(binString);
};

const sha256Digest = async (message: string): Promise<ArrayBuffer> => {
	const encoder = new TextEncoder();
	const data = encoder.encode(message);

	if (typeof crypto === 'undefined' || typeof crypto.subtle === 'undefined') {
		throw new Error('Web Crypto API is not available.');
	}
	return crypto.subtle.digest('SHA-256', data);
};

const base64UrlDecode = (input: string): string => {
	const output: string = input.replaceAll('-', '+').replaceAll('_', '/');
	switch (output.length % 4) {
		case 0:
			break;
		case 2:
			output += '==';
			break;
		case 3:
			output += '=';
			break;
		default:
			throw new Error('Input is not of the correct length.');
	}
	try {
		return b64DecodeUnicode(output);
	} catch (error) {
		return atob(output);
	}
};

const b64DecodeUnicode = (input: string): string => {
	return decodeURIComponent(
		atob(input).replace(/(.)/g, (_m, p: string) => {
			const originalCode: string = p.charCodeAt(0).toString(16).toUpperCase();
			const code: string = originalCode.length < 2 ? '0' + originalCode : originalCode;
			return '%' + code;
		}),
	);
};

const decodeToken = <T extends IKeycloakTokenParsed = IKeycloakTokenParsed>(token: string): T => {
	const [, payload] = token.split('.');

	if (typeof payload !== 'string') {
		throw new Error('Unable to decode token, payload not found.');
	}

	const decoded: string = base64UrlDecode(payload); // base64UrlDecode handles its own errors

	try {
		return JSON.parse(decoded) as T;
	} catch (error) {
		throw new Error('Unable to decode token, payload is not a valid JSON value.', { cause: error });
	}
};


// NetworkError class
export interface INetworkErrorOptions extends ErrorOptions {
	response: Response;
}

export class NetworkError extends Error {
	public response: Response;

	constructor(message: string, options: INetworkErrorOptions) {
		super(message, options);
		this.name = 'NetworkError';
		this.response = options.response;
	}
}


// JSON Config types (for fetching config files)
interface IJsonConfig {
	'auth-server-url': string;
	realm: string;
	resource: string; // client_id
}

interface IOpenIdProviderMetadata {
	authorization_endpoint: string;
	token_endpoint: string;
	userinfo_endpoint?: string;
	check_session_iframe?: string;
	end_session_endpoint?: string;
	[key: string]: unknown; // Allow other properties
}


// Internal type for parsed callback
interface IParsedCallback {
	code?: string;
	error?: string;
	error_description?: string;
	error_uri?: string;
	state?: string;
	session_state?: string;
	kc_action_status?: string;
	kc_action?: string;
	iss?: string;
	access_token?: string;
	token_type?: string;
	id_token?: string;
	expires_in?: string;
	
	newUrl: string; // The URL after consuming known OAuth params
	valid: boolean;
	redirectUri: string;
	storedNonce?: string;
	prompt?: string;
	pkceCodeVerifier?: string;
	loginOptions?: ILoginOptions;
}


// Main Keycloak Class
class Keycloak {
	// --- Configuration store ---
	#config: IKeycloakConfig | string; // Can be string initially if URL is passed
	#initOptions: IKeycloakInitOptions = {};

	// --- Internal State ---
	#adapter?: IKeycloakAdapter;
	#refreshQueue: Array<{ resolve: (value: boolean) => void; reject: (reason?: unknown) => void }> = [];
	#isRefreshingToken = false; // Flag to indicate a refresh is in progress
	#callbackStorage?: ICallbackStorage;

	#loginIframe: {
		enable: boolean;
		// Stores {resolve, reject} for promises returned by #checkLoginIframe when multiple calls are made
		callbackList: Array<{ resolve: (value: boolean) => void; reject: (reason?: unknown) => void }>;
		interval: number;
		iframe?: HTMLIFrameElement;
		iframeOrigin?: string;
	} = {
		enable: true,
		callbackList: [],
		interval: 5,
	};

	#didInitialize = false;
	#useNonce = true;
	#enableLogging = false;

	// --- Token and Session Information ---
	public authenticated = false;
	public token?: string;
	public tokenParsed?: IKeycloakTokenParsed;
	public refreshToken?: string;
	public refreshTokenParsed?: IKeycloakTokenParsed;
	public idToken?: string;
	public idTokenParsed?: IKeycloakTokenParsed;
	public timeSkew?: number;
	public loginRequired?: boolean;
	public responseMode?: 'query' | 'fragment';
	public responseType?: 'code' | 'id_token token' | 'code id_token token';
	public flow?: 'standard' | 'implicit' | 'hybrid';
	public redirectUri?: string;
	public silentCheckSsoRedirectUri?: string;
	public silentCheckSsoFallback = true;
	public pkceMethod: 'S256' | false = 'S256';
	public logoutMethod: 'POST' | 'GET' = 'GET';
	public scope?: string;
	public messageReceiveTimeout = 10000;
	public sessionId?: string;
	public subject?: string;
	public realmAccess?: IKeycloakRoles;
	public resourceAccess?: IKeycloakResourceAccess;
	public profile?: IKeycloakProfile;
	public userInfo?: unknown; // To be typed: IUserInfo
	public authServerUrl?: string;
	public realm?: string;
	public clientId?: string;

	#tokenTimeoutHandle?: number; // For setTimeout return value

	// --- Event Handlers (public properties) ---
	public onReady?: KeycloakOnReady;
	public onAuthSuccess?: KeycloakOnAuthSuccess;
	public onAuthError?: KeycloakOnAuthError;
	public onAuthRefreshSuccess?: KeycloakOnAuthRefreshSuccess;
	public onAuthRefreshError?: KeycloakOnAuthRefreshError;
	public onAuthLogout?: KeycloakOnAuthLogout;
	public onTokenExpired?: KeycloakOnTokenExpired;
	public onActionUpdate?: KeycloakOnActionUpdate;

	// --- Endpoints ---
	#endpoints?: {
		authorize: () => string;
		token: () => string;
		logout: () => string;
		checkSessionIframe?: () => string;
		thirdPartyCookiesIframe?: () => string;
		register: () => string;
		userinfo: () => string;
	};


	constructor(config: KeycloakConfig) {
		if (typeof config === 'string') {
			// Config is a URL, needs to be fetched.
			// This will be handled in #loadConfig, for now, store as string
			// and mark it for async loading.
			// For simplicity in this step, we'll assume it's an object for now.
			// TODO: Handle string config properly in init() or a private load method.
			throw new Error('String configuration (URL) is not yet fully implemented in this refactoring step.');
		} else if (!isObject(config)) {
			throw new Error("The 'Keycloak' constructor must be provided with a configuration object or a URL to a JSON configuration file.");
		}

		const currentConfig: IKeycloakConfig = config as IKeycloakConfig;
		this.#config = { ...currentConfig }; // Shallow copy

		// Handle deprecated config properties
		if (currentConfig['auth-server-url']) {
			this.#config.url = this.#config.url || currentConfig['auth-server-url'];
		}
		if (currentConfig.resource) {
			this.#config.clientId = this.#config.clientId || currentConfig.resource;
		}
		
		// Validate required properties
		const requiredProperties: string[] = 'oidcProvider' in this.#config
			? ['clientId']
			: ['url', 'realm', 'clientId'];

		for (const property of requiredProperties) {
			if (!this.#config[property as keyof IKeycloakConfig]) {
				throw new Error(`The configuration object is missing the required '${property}' property.`);
			}
		}
		
		this.clientId = this.#config.clientId;
		this.realm = this.#config.realm;
		this.authServerUrl = this.#config.url;


		if (!globalThis.isSecureContext) {
			this.#logWarn(
				"[KEYCLOAK] Keycloak JS must be used in a 'secure context' to function properly as it relies on browser APIs that are otherwise not available.
" +
				"Continuing to run your application insecurely will lead to unexpected behavior and breakage.

" +
				"For more information see: https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts"
			);
		}
	}

	#logInfo(...args: unknown[]): void {
		if (this.#enableLogging) {
			console.info('[KEYCLOAK]', ...args);
		}
	}

	#logWarn(...args: unknown[]): void {
		if (this.#enableLogging) {
			console.warn('[KEYCLOAK]', ...args);
		}
	}


	public async init(initOptions: IKeycloakInitOptions = {}): Promise<boolean> {
		if (this.#didInitialize) {
			throw new Error("A 'Keycloak' instance can only be initialized once.");
		}
		this.#didInitialize = true;
		this.#initOptions = { ...initOptions }; // Shallow copy

		this.authenticated = false; // Reset authenticated status

		this.#callbackStorage = this.#createCallbackStorage();
		this.#adapter = this.#loadAdapter(initOptions.adapter);

		if (typeof initOptions.useNonce !== 'undefined') {
			this.#useNonce = initOptions.useNonce;
		}

		if (typeof initOptions.checkLoginIframe !== 'undefined') {
			this.#loginIframe.enable = initOptions.checkLoginIframe;
		}

		if (initOptions.checkLoginIframeInterval) {
			this.#loginIframe.interval = initOptions.checkLoginIframeInterval;
		}

		if (initOptions.onLoad === 'login-required') {
			this.loginRequired = true;
		}

		if (initOptions.responseMode) {
			if (initOptions.responseMode === 'query' || initOptions.responseMode === 'fragment') {
				this.responseMode = initOptions.responseMode;
			} else {
				throw new Error('Invalid value for responseMode');
			}
		}

		if (initOptions.flow) {
			switch (initOptions.flow) {
				case 'standard':
					this.responseType = 'code';
					break;
				case 'implicit':
					this.responseType = 'id_token token';
					break;
				case 'hybrid':
					this.responseType = 'code id_token token';
					break;
				default:
					throw new Error('Invalid value for flow');
			}
			this.flow = initOptions.flow;
		}

		if (initOptions.timeSkew != null) {
			this.timeSkew = initOptions.timeSkew;
		}

		if (initOptions.redirectUri) {
			this.redirectUri = initOptions.redirectUri;
		}

		if (initOptions.silentCheckSsoRedirectUri) {
			this.silentCheckSsoRedirectUri = initOptions.silentCheckSsoRedirectUri;
		}

		if (typeof initOptions.silentCheckSsoFallback === 'boolean') {
			this.silentCheckSsoFallback = initOptions.silentCheckSsoFallback;
		} else {
			this.silentCheckSsoFallback = true; // Default value
		}

		if (typeof initOptions.pkceMethod !== 'undefined') {
			if (initOptions.pkceMethod !== 'S256' && initOptions.pkceMethod !== false) {
				throw new TypeError(`Invalid value for pkceMethod, expected 'S256' or false but got ${initOptions.pkceMethod}.`);
			}
			this.pkceMethod = initOptions.pkceMethod;
		} else {
			this.pkceMethod = 'S256'; // Default value
		}

		if (typeof initOptions.enableLogging === 'boolean') {
			this.#enableLogging = initOptions.enableLogging;
		} else {
			this.#enableLogging = false; // Default value
		}
		
		if (initOptions.logoutMethod === 'POST') {
			this.logoutMethod = 'POST';
		} else {
			this.logoutMethod = 'GET'; // Default value
		}

		if (typeof initOptions.scope === 'string') {
			this.scope = initOptions.scope;
		}

		if (typeof initOptions.messageReceiveTimeout === 'number' && initOptions.messageReceiveTimeout > 0) {
			this.messageReceiveTimeout = initOptions.messageReceiveTimeout;
		} else {
			this.messageReceiveTimeout = 10000; // Default value
		}

		// Set default responseMode and responseType if not provided
		if (!this.responseMode) {
			this.responseMode = 'fragment';
		}
		if (!this.responseType) {
			this.responseType = 'code';
			this.flow = 'standard';
		}
		
		try {
			await this.#loadConfig(); // Load configuration (might be async if config was a URL string)
			await this.#check3pCookiesSupported(); // Check for 3rd party cookie support
			await this.#processInit(); // Main initialization logic

			this.onReady?.(this.authenticated);
			return this.authenticated;
		} catch (error: unknown) {
			this.#logWarn('[KEYCLOAK] Error during Keycloak initialization:', error);
			// Ensure #config is an object before trying to access properties for error construction
			const configIsObject: boolean = typeof this.#config === 'object' && this.#config !== null;
			const errorData: IKeycloakError = error instanceof Error ?
				{ error: error.name, error_description: error.message } :
				{ error: 'initialization_error', error_description: String(error) }; // Explicitly convert error to string
			
			if (configIsObject && (this.#config as IKeycloakConfig).url && (this.#config as IKeycloakConfig).realm && (this.#config as IKeycloakConfig).clientId) {
				// Only call onAuthError if basic config seems to be loaded
				this.onAuthError?.(errorData);
			}
			// Re-throw the error to be caught by the caller of init, or if they prefer,
			// they can rely on onAuthError and onReady(false)
			throw error; 
		}
	}

	async #loadConfig(): Promise<void> {
		if (typeof this.#config === 'string') {
		const configUrl: string = this.#config;
			this.#logInfo('[KEYCLOAK] Fetching configuration from URL:', configUrl);
			try {
			const fetchedConfig: IJsonConfig = await Keycloak.#fetchJsonConfig(configUrl);
				// Update #config to be the fetched object.
				this.#config = { 
					url: fetchedConfig['auth-server-url'], // The key in keycloak.json is 'auth-server-url'
					realm: fetchedConfig.realm,
					clientId: fetchedConfig.resource, // The key in keycloak.json is 'resource'
				};
				// Update instance properties that were derived from config in constructor
				this.clientId = this.#config.clientId;
				this.realm = this.#config.realm;
				this.authServerUrl = this.#config.url;
		} catch (e: unknown) {
				throw new Error(`Failed to load keycloak.json from ${configUrl}`, {cause: e});
			}
		}

		// Ensure #config is an object now
		if (typeof this.#config !== 'object' || this.#config === null) {
			throw new Error("Keycloak configuration is not an object.");
		}

	const oidcProvider: string | IOpenIdProviderMetadata | undefined = (this.#config as IKeycloakConfig).oidcProvider;

		if (typeof oidcProvider === 'string') {
		const oidcProviderConfigUrl: string = oidcProvider.endsWith('/')
				? `${oidcProvider}.well-known/openid-configuration`
				: `${oidcProvider}/.well-known/openid-configuration`;
			try {
			const metadata: IOpenIdProviderMetadata = await Keycloak.#fetchOpenIdConfig(oidcProviderConfigUrl);
				this.#setupOidcEndpoints(metadata);
		} catch (e: unknown) {
				throw new Error(`Failed to load OIDC provider configuration from ${oidcProviderConfigUrl}`, {cause: e});
			}
		} else if (isObject(oidcProvider)) {
			this.#setupOidcEndpoints(oidcProvider as IOpenIdProviderMetadata);
		} else {
			this.#setupOidcEndpoints(null); // Standard Keycloak endpoints
		}
	}

	#getRealmUrl(): string | undefined {
		// Ensure #config is an object before accessing its properties
	if (typeof this.#config !== 'object' || this.#config === null) { // Assuming #config is IKeycloakConfig by this point
			return undefined; 
		}
		if (typeof this.authServerUrl !== 'undefined' && typeof this.realm !== 'undefined') {
		const authServerUrl: string = this.authServerUrl.endsWith('/') ? this.authServerUrl : `${this.authServerUrl}/`;
			return `${authServerUrl}realms/${encodeURIComponent(this.realm)}`;
		}
		return undefined;
	}


	#setupOidcEndpoints(oidcConfiguration: IOpenIdProviderMetadata | null): void {
		if (!oidcConfiguration) {
		const realmUrl: string | undefined = this.#getRealmUrl();
			if (!realmUrl) {
				throw new Error('Cannot setup endpoints: authServerUrl and realm must be configured.');
			}
			this.#endpoints = {
				authorize: () => `${realmUrl}/protocol/openid-connect/auth`,
				token: () => `${realmUrl}/protocol/openid-connect/token`,
				logout: () => `${realmUrl}/protocol/openid-connect/logout`,
				checkSessionIframe: () => `${realmUrl}/protocol/openid-connect/login-status-iframe.html`,
				thirdPartyCookiesIframe: () => `${realmUrl}/protocol/openid-connect/3p-cookies/step1.html`,
				register: () => `${realmUrl}/protocol/openid-connect/registrations`,
				userinfo: () => `${realmUrl}/protocol/openid-connect/userinfo`,
			};
		} else {
			this.#endpoints = {
				authorize: () => oidcConfiguration.authorization_endpoint,
				token: () => oidcConfiguration.token_endpoint,
				logout: () => {
					if (!oidcConfiguration.end_session_endpoint) {
						throw new Error('Logout not supported by the OIDC server: end_session_endpoint missing.');
					}
					return oidcConfiguration.end_session_endpoint;
				},
				checkSessionIframe: oidcConfiguration.check_session_iframe ? () => oidcConfiguration.check_session_iframe! : undefined,
				thirdPartyCookiesIframe: undefined, // Not applicable for generic OIDC
				register: () => {
					throw new Error('Redirection to "Register user" page not supported in standard OIDC mode.');
				},
				userinfo: () => {
					if (!oidcConfiguration.userinfo_endpoint) {
						throw new Error('UserInfo not supported by the OIDC server: userinfo_endpoint missing.');
					}
					return oidcConfiguration.userinfo_endpoint;
				},
			};
		}
	}

	#loadAdapter(adapterConfig?: 'default' | 'cordova' | 'cordova-native' | IKeycloakAdapter): IKeycloakAdapter {
		if (typeof adapterConfig === 'object') {
			return adapterConfig;
		}

	const type: 'default' | 'cordova' | 'cordova-native' = adapterConfig || (window.Cordova || (window as any).cordova ? 'cordova' : 'default');

		switch (type) {
			case 'default':
				return {
					login: async (options?: ILoginOptions): Promise<void> => {
						window.location.assign(await this.createLoginUrl(options));
					},
					logout: async (options?: ILogoutOptions): Promise<void> => {
					const logoutMethod: 'POST' | 'GET' = options?.logoutMethod ?? this.logoutMethod;
					const logoutUrl: string = this.createLogoutUrl(options);

						if (logoutMethod === 'GET') {
							window.location.replace(logoutUrl);
							return;
						}
						// POST logout
					const form: HTMLFormElement = document.createElement('form');
						form.setAttribute('method', 'POST');
						form.setAttribute('action', logoutUrl);
						form.style.display = 'none';

					const data: { id_token_hint: string | undefined; client_id: string | undefined; post_logout_redirect_uri: string | undefined; } = {
							id_token_hint: this.idToken,
							client_id: this.clientId,
							post_logout_redirect_uri: this.#adapter?.redirectUri(options),
						};

						for (const [name, value] of Object.entries(data)) {
							if (value) {
							const input: HTMLInputElement = document.createElement('input');
								input.setAttribute('type', 'hidden');
								input.setAttribute('name', name);
								input.setAttribute('value', value);
								form.appendChild(input);
							}
						}
						document.body.appendChild(form);
						form.submit();
					},
					register: async (options?: IRegisterOptions): Promise<void> => {
						window.location.assign(await this.createRegisterUrl(options));
					},
					accountManagement: async (): Promise<void> => {
					const accountUrl: string | undefined = this.createAccountUrl();
						if (typeof accountUrl !== 'undefined') {
							window.location.href = accountUrl;
						} else {
							throw new Error('Account management not supported by the OIDC server.');
						}
					},
					redirectUri: (options?: { redirectUri?: string }): string => {
						return options?.redirectUri || this.redirectUri || window.location.href;
					},
				};

			case 'cordova':
			case 'cordova-native': // cordova-native can reuse much of cordova logic with specific overrides
				this.#loginIframe.enable = false;
				// eslint-disable-next-line no-case-declarations
				const isNative = type === 'cordova-native';

				// eslint-disable-next-line no-case-declarations
				const cordovaOpenWindowWrapper = (loginUrl: string, target: string, options: string) => {
					if (isNative) {
						if (!window.cordova?.plugins?.browsertab) {
							throw new Error('Cordova BrowserTab plugin is not available.');
						}
						window.cordova.plugins.browsertab.openUrl(loginUrl);
						// For native, the promise resolves/rejects based on universalLinks subscription
						return { close: () => window.cordova?.plugins?.browsertab?.close() }; // Provide a close method
					} else {
						if (!window.cordova?.InAppBrowser) {
							throw new Error('Cordova InAppBrowser plugin is not available.');
						}
						return window.cordova.InAppBrowser.open(loginUrl, target, options);
					}
				};
				
				// eslint-disable-next-line no-case-declarations
				const getCordovaRedirectUri = (): string => this.redirectUri || (isNative ? 'http://localhost' : 'http://localhost');


				return {
					login: (options?: ILoginOptions): Promise<void> => {
						return new Promise(async (resolve, reject) => {
							const loginUrl = await this.createLoginUrl(options);
							let completed = false;

							const universalLinksListener = (event: { url: string }): void => {
								if (isNative && event.url.startsWith(getCordovaRedirectUri())) {
									window.universalLinks?.unsubscribe('keycloak'); // Assuming 'keycloak' is the event name
									cordovaOpenWindowWrapper('', '', '').close?.(); // Close the browser tab
									const oauth = this.#parseCallback(event.url);
									if (oauth) this.#processCallback(oauth).then(() => resolve()).catch(e => reject(e));
									else reject(new Error('Failed to parse callback from universal link'));
									completed = true;
								}
							};

							if (isNative) {
								window.universalLinks?.subscribe('keycloak', universalLinksListener);
							}
							
							const ref = cordovaOpenWindowWrapper(loginUrl, '_blank', 'location=no,hidden=yes,clearcache=yes');
							if (!isNative && ref?.addEventListener) {
								ref.addEventListener('loadstart', (event: { url: string }) => {
									if (event.url.startsWith(getCordovaRedirectUri())) {
										const oauth = this.#parseCallback(event.url);
										if (oauth) this.#processCallback(oauth).then(() => resolve()).catch(e => reject(e));
										else reject(new Error('Failed to parse callback from loadstart'));
										ref.close();
										completed = true;
									}
								});
								ref.addEventListener('loaderror', () => {
									if (!completed) {
										reject(new Error('Failed to load login page'));
									}
								});
								ref.addEventListener('exit', () => {
									if (!completed) {
										reject(new Error('Login cancelled by user'));
									}
								});
							} else if (isNative && !window.universalLinks) {
								reject(new Error('Universal Links plugin is not available for native login.'));
							}
						});
					},
					logout: (options?: ILogoutOptions): Promise<void> => {
						return new Promise(async (resolve, reject) => {
							const logoutUrl = this.createLogoutUrl(options);
							let completed = false;

							const universalLinksListener = (event: { url: string }): void => {
								if (isNative && event.url.startsWith(getCordovaRedirectUri())) {
									window.universalLinks?.unsubscribe('keycloak');
									cordovaOpenWindowWrapper('', '', '').close?.();
									this.clearToken();
									resolve();
									completed = true;
								}
							};

							if (isNative) {
								window.universalLinks?.subscribe('keycloak', universalLinksListener);
							}

							const ref = cordovaOpenWindowWrapper(logoutUrl, '_blank', 'location=no,hidden=yes,clearcache=yes');
							if (!isNative && ref?.addEventListener) {
								ref.addEventListener('loadstart', (event: { url: string }) => {
									if (event.url.startsWith(getCordovaRedirectUri())) {
										ref.close();
										this.clearToken();
										resolve();
										completed = true;
									}
								});
								ref.addEventListener('loaderror', () => {
									if(!completed) reject(new Error('Failed to load logout page'));
								});
								ref.addEventListener('exit', () => {
									if (!completed) {
										this.clearToken(); // Assume logout happened even if exit was unexpected
										resolve();
									}
								});
							} else if (isNative && !window.universalLinks) {
								reject(new Error('Universal Links plugin is not available for native logout.'));
							}
						});
					},
					register: (options?: IRegisterOptions): Promise<void> => {
						// Similar to login, using createRegisterUrl
						return new Promise(async (resolve, reject) => {
							const registerUrl = await this.createRegisterUrl(options);
							let completed = false;

							const universalLinksListener = (event: { url: string }): void => {
								if (isNative && event.url.startsWith(getCordovaRedirectUri())) {
									window.universalLinks?.unsubscribe('keycloak');
									cordovaOpenWindowWrapper('', '', '').close?.();
									const oauth = this.#parseCallback(event.url);
									if (oauth) this.#processCallback(oauth).then(() => resolve()).catch(e => reject(e));
									else reject(new Error('Failed to parse callback from universal link for registration'));
									completed = true;
								}
							};
							if (isNative) {
								window.universalLinks?.subscribe('keycloak', universalLinksListener);
							}
							
							const ref = cordovaOpenWindowWrapper(registerUrl, '_blank', 'location=no,hidden=yes');
							if (!isNative && ref?.addEventListener) {
								ref.addEventListener('loadstart', (event: { url: string }) => {
									if (event.url.startsWith(getCordovaRedirectUri())) {
										ref.close();
										const oauth = this.#parseCallback(event.url);
										if (oauth) this.#processCallback(oauth).then(() => resolve()).catch(e => reject(e));
										else reject(new Error('Failed to parse callback from loadstart for registration'));
										completed = true;
									}
								});
								ref.addEventListener('loaderror', () => {
									if(!completed) reject(new Error('Failed to load registration page'));
								});
								ref.addEventListener('exit', () => {
									if(!completed) reject(new Error('Registration cancelled by user'));
								});
							} else if (isNative && !window.universalLinks) {
								reject(new Error('Universal Links plugin is not available for native registration.'));
							}
						});
					},
					accountManagement: (): Promise<void> => {
						return new Promise(async (resolve, reject) => {
							const accountUrl = this.createAccountUrl();
							if (!accountUrl) {
								reject(new Error('Account URL is not available.'));
								return;
							}
							if (isNative) {
								cordovaOpenWindowWrapper(accountUrl, '', '');
								// Native account management might not have a direct "completion" callback via universal links
								// It opens an external browser. Assume success once opened.
								resolve();
							} else {
								const ref = cordovaOpenWindowWrapper(accountUrl, '_blank', 'location=no');
								if (ref?.addEventListener) {
									ref.addEventListener('loadstart', (event: { url: string }) => {
										if (event.url.startsWith(getCordovaRedirectUri())) {
											ref.close(); // Close if it tries to redirect back to app, not typical for account mgmt
										}
									});
									ref.addEventListener('exit', () => resolve()); // Resolve when InAppBrowser is closed
									ref.addEventListener('loaderror', () => reject(new Error('Failed to load account management page')));
								}
							}
						});
					},
					redirectUri: (options?: { redirectUri?: string }): string => {
						if (options?.redirectUri) return options.redirectUri;
						return getCordovaRedirectUri();
					},
				};
			default:
				throw new Error('Invalid adapter type: ' + type);
		}
	}

	#createCallbackStorage(): ICallbackStorage {
		try {
			// Try LocalStorage first
			localStorage.setItem('kc-test', 'test');
			localStorage.removeItem('kc-test');
			return new KeycloakLocalStorage();
	} catch (err: unknown) {
			// Fallback to CookieStorage
			return new KeycloakCookieStorage();
		}
	}

	// --- Public API Methods (signatures, basic implementation) ---

	public async login(options?: ILoginOptions): Promise<void> {
		if (!this.#adapter) throw new Error('Adapter not initialized.');
		return this.#adapter.login(options);
	}
	
	public async createLoginUrl(options?: ILoginOptions): Promise<string> {
		if (!this.#endpoints) throw new Error('Endpoints not initialized.');
		if (!this.#callbackStorage) throw new Error('Callback storage not initialized.');

		const state = Keycloak.#createUUID();
		const nonce = Keycloak.#createUUID();
		const redirectUri = this.#adapter?.redirectUri(options) || window.location.href;

		const callbackState: ICallbackStorageState = {
			state,
			nonce,
			redirectUri: encodeURIComponent(redirectUri),
			loginOptions: options,
		};

		if (options?.prompt) {
			callbackState.prompt = options.prompt;
		}
		
		const url = options?.action === 'register'
			? this.#endpoints.register()
			: this.#endpoints.authorize();

		let currentScope = options?.scope || this.scope;
		const scopeValues = currentScope ? currentScope.split(' ') : [];
		if (!scopeValues.includes('openid')) {
			scopeValues.unshift('openid');
		}
		currentScope = scopeValues.join(' ');

		const params = new URLSearchParams({
			client_id: this.clientId!,
			redirect_uri: redirectUri,
			state: state,
			response_mode: this.responseMode!,
			response_type: this.responseType!,
			scope: currentScope,
		});

		if (this.#useNonce) {
			params.append('nonce', nonce);
		}

		if (options?.prompt) params.append('prompt', options.prompt);
		if (typeof options?.maxAge === 'number') params.append('max_age', options.maxAge.toString());
		if (options?.loginHint) params.append('login_hint', options.loginHint);
		if (options?.idpHint) params.append('kc_idp_hint', options.idpHint);
		if (options?.action && options.action !== 'register') params.append('kc_action', options.action);
		if (options?.locale) params.append('ui_locales', options.locale);
		
		if (options?.acr) {
			// In OIDC, acr_values is a space-separated string.
			// The original code used `buildClaimsParameter` for options.acr.
			// Let's stick to acr_values for simplicity if acr is a simple string.
			// If options.acr is meant to be complex claims, then buildClaimsParameter is needed.
			// Assuming options.acr is a simple string for acr_values based on ILoginOptions.
			params.append('acr_values', options.acr);
		}
		// If options.acrValues is also present (e.g. from a more specific use case), append it.
		// This might lead to two acr_values params if both are used, which is unusual.
		// The original code's buildClaimsParameter only handled options.acr for id_token.
		if (options?.acrValues) {
			params.append('acr_values', options.acrValues);
		}


		if (this.pkceMethod) {
			try {
				const codeVerifier = Keycloak.#generateCodeVerifier(96);
				const pkceChallenge = await Keycloak.#generatePkceChallenge(this.pkceMethod, codeVerifier);
				callbackState.pkceCodeVerifier = codeVerifier;
				params.append('code_challenge', pkceChallenge);
				params.append('code_challenge_method', this.pkceMethod);
			} catch (error) {
				throw new Error('Failed to generate PKCE challenge.', { cause: error });
			}
		}
		this.#callbackStorage.add(callbackState);
		return `${url}?${params.toString()}`;
	}

	public async logout(options?: ILogoutOptions): Promise<void> {
		if (!this.#adapter) throw new Error('Adapter not initialized.');
		return this.#adapter.logout(options);
	}

	public createLogoutUrl(options?: ILogoutOptions): string {
		if (!this.#endpoints) throw new Error('Endpoints not initialized.');
		const logoutMethod = options?.logoutMethod ?? this.logoutMethod;
		const url = this.#endpoints.logout();

		if (logoutMethod === 'POST') {
			return url; // For POST, the URL is just the endpoint itself. Parameters are sent in body.
		}
		
		// For GET requests
		const params = new URLSearchParams({
			client_id: this.clientId!,
		});

		const redirectUri = this.#adapter?.redirectUri(options);
		if (redirectUri) {
			params.append('post_logout_redirect_uri', redirectUri);
		}

		if (this.idToken) {
			params.append('id_token_hint', this.idToken);
		}
		return `${url}?${params.toString()}`;
	}
	
	public async register(options?: IRegisterOptions): Promise<void> {
		if (!this.#adapter) throw new Error('Adapter not initialized.');
		return this.#adapter.register(options);
	}

	public async createRegisterUrl(options?: IRegisterOptions): Promise<string> {
		return this.createLoginUrl({ ...options, action: 'register' });
	}

	public createAccountUrl(options?: IAccountOptions): string | undefined {
		const realmUrl = this.#getRealmUrl();
		if (!realmUrl || this.#config.oidcProvider) { // Account URL not applicable for generic OIDC
			this.#logWarn('Account management is not available when using a generic OIDC provider.');
			return undefined;
		}

		const params = new URLSearchParams({
			referrer: this.clientId!,
		});
		const redirectUri = this.#adapter?.redirectUri(options);
		if (redirectUri) {
			params.append('referrer_uri', redirectUri);
		}
		return `${realmUrl}/account?${params.toString()}`;
	}

	public async accountManagement(): Promise<void> {
		if (!this.#adapter) throw new Error('Adapter not initialized.');
		return this.#adapter.accountManagement();
	}

	public hasRealmRole(role: string): boolean {
		return !!this.realmAccess && this.realmAccess.roles.includes(role);
	}

	public hasResourceRole(role: string, resource?: string): boolean {
		if (!this.resourceAccess) return false;
		const access = this.resourceAccess[resource || this.clientId!];
		return !!access && access.roles.includes(role);
	}
	
	public async loadUserProfile(): Promise<IKeycloakProfile> {
		if (!this.#endpoints?.userinfo && !this.#getRealmUrl()) { // Prefer userinfo, fallback to account if Keycloak specific
			throw new Error('Cannot load user profile: UserInfo endpoint or realm URL is not configured.');
		}

		const url = this.#endpoints?.userinfo ? this.#endpoints.userinfo() : `${this.#getRealmUrl()}/account`;
		
		const profile = await Keycloak.#fetchJSON<IKeycloakProfile>(url, {
			headers: Keycloak.#buildAuthorizationHeader(this.token),
		});
		this.profile = profile;
		return profile;
	}

	public async loadUserInfo(): Promise<unknown> { // Replace unknown with IUserInfo
		if (!this.#endpoints?.userinfo) {
			throw new Error('Cannot load user info: UserInfo endpoint is not configured.');
		}
		const url = this.#endpoints.userinfo();
		const userInfo = await Keycloak.#fetchJSON<unknown>(url, { // Replace unknown with IUserInfo
			headers: Keycloak.#buildAuthorizationHeader(this.token),
		});
		this.userInfo = userInfo;
		return userInfo;
	}

	public isTokenExpired(minValidity = 0): boolean {
		if (!this.tokenParsed || (!this.refreshToken && this.flow !== 'implicit')) {
			throw new Error('Not authenticated or missing token information.');
		}
		if (this.timeSkew == null) {
			this.#logInfo('Unable to determine if token is expired as timeskew is not set');
			return true; // Assume expired if timeskew is unknown
		}
		const expiresIn = (this.tokenParsed.exp ?? 0) - Math.ceil(Date.now() / 1000) + this.timeSkew;
		if (minValidity < 0) throw new Error('Invalid minValidity');
		return expiresIn < minValidity;
	}

	public updateToken(minValidity?: number): Promise<boolean> {
		return new Promise<boolean>((resolve, reject) => {
			if (!this.refreshToken) {
				this.#logWarn('[KEYCLOAK] No refresh token available. Cannot update token.');
				reject(new Error('No refresh token available')); // Or resolve(false) depending on desired behavior
				return;
			}

			const validity = minValidity ?? 5; // Default to 5 seconds if not specified

			const execRefresh = async () => {
				if (!this.#isRefreshingToken) {
					this.#isRefreshingToken = true;
					this.#refreshQueue.push({ resolve, reject }); // Add current promise's handlers to queue

					try {
						const shouldRefreshToken = validity === -1 || !this.tokenParsed || this.isTokenExpired(validity);

						if (!shouldRefreshToken) {
							this.#logInfo('[KEYCLOAK] Token not expired, no refresh needed.');
							this.#resolveAllRefreshRequests(false); // Resolve all queued promises with false
							return;
						}

						this.#logInfo(validity === -1 ? '[KEYCLOAK] Refreshing token: forced refresh' : '[KEYCLOAK] Refreshing token: token expired or minValidity not met');
						
						const timeLocal = Date.now();
						// Ensure endpoints are available
						if (!this.#endpoints?.token) {
							throw new Error("Token endpoint not available");
						}
						const tokenResponse = await Keycloak.#fetchRefreshToken(this.#endpoints.token(), this.refreshToken!, this.clientId!);
						
						const newAccessToken = tokenResponse.access_token;
						const newRefreshToken = tokenResponse.refresh_token;
						const newIdToken = tokenResponse.id_token;

						this.#logInfo('[KEYCLOAK] Token refreshed');
						const newTimeLocal = (timeLocal + Date.now()) / 2;
						this.#setToken(newAccessToken, newRefreshToken, newIdToken, newTimeLocal);

						this.onAuthRefreshSuccess?.();
						this.#resolveAllRefreshRequests(true);
					} catch (error) {
						this.#logWarn('[KEYCLOAK] Failed to refresh token', error);
						if (error instanceof NetworkError && error.response?.status === 400) {
							this.clearToken(); // Clears tokens and calls onAuthLogout
						}
						this.onAuthRefreshError?.();
						this.#rejectAllRefreshRequests(error);
					} finally {
						this.#isRefreshingToken = false;
					}
				} else {
					// If a refresh is already in progress, add this promise's handlers to the queue
					this.#logInfo('[KEYCLOAK] Token refresh already in progress. Queuing request.');
					this.#refreshQueue.push({ resolve, reject });
				}
			};

			// Wrapped execRefresh in an async IIFE to handle potential errors from #checkLoginIframe
			(async () => {
				try {
					if (this.#loginIframe.enable) {
						await this.#checkLoginIframe(); // Wait for iframe check to complete
					}
					await execRefresh();
				} catch (iframeError) {
					this.#logWarn('[KEYCLOAK] Error during iframe check in updateToken', iframeError);
					reject(iframeError); // Error from iframe check
				}
			})();
		});
	}

	#resolveAllRefreshRequests(value: boolean): void {
		for (const p of this.#refreshQueue) {
			p.resolve(value);
		}
		this.#refreshQueue = [];
	}
	
	#rejectAllRefreshRequests(reason: unknown): void {
		for (const p of this.#refreshQueue) {
			p.reject(reason);
		}
		this.#refreshQueue = [];
	}

	public clearToken(): void {
		if (this.token) {
			this.#setToken(null, null, null); // Clears tokens and parsed info
			this.onAuthLogout?.();
			if (this.loginRequired) {
				this.login().catch(e => this.#logWarn('Login after token clear failed', e));
			}
		}
	}
	
	#setToken(token: string | null, refreshToken: string | null, idToken: string | null, timeLocal?: number): void {
		if (this.#tokenTimeoutHandle) {
			clearTimeout(this.#tokenTimeoutHandle);
			this.#tokenTimeoutHandle = undefined;
		}

		if (refreshToken) {
			this.refreshToken = refreshToken;
			this.refreshTokenParsed = decodeToken(refreshToken);
		} else {
			this.refreshToken = undefined;
			this.refreshTokenParsed = undefined;
		}

		if (idToken) {
			this.idToken = idToken;
			this.idTokenParsed = decodeToken(idToken);
		} else {
			this.idToken = undefined;
			this.idTokenParsed = undefined;
		}

		if (token) {
			this.token = token;
			this.tokenParsed = decodeToken(token);
			this.sessionId = this.tokenParsed.sid;
			this.authenticated = true;
			this.subject = this.tokenParsed.sub;
			this.realmAccess = this.tokenParsed.realm_access;
			this.resourceAccess = this.tokenParsed.resource_access;

			if (timeLocal && this.tokenParsed.iat) {
				this.timeSkew = Math.floor(timeLocal / 1000) - this.tokenParsed.iat;
			}

			if (this.timeSkew != null) {
				this.#logInfo('Estimated time difference between browser and server is ' + this.timeSkew + ' seconds');
				if (this.onTokenExpired && this.tokenParsed.exp) {
					const expiresIn = (this.tokenParsed.exp - (Date.now() / 1000) + this.timeSkew) * 1000;
					this.#logInfo('Token expires in ' + Math.round(expiresIn / 1000) + ' s');
					if (expiresIn <= 0) {
						this.onTokenExpired();
					} else {
						this.#tokenTimeoutHandle = window.setTimeout(this.onTokenExpired, expiresIn);
					}
				}
			}
		} else {
			this.token = undefined;
			this.tokenParsed = undefined;
			this.subject = undefined;
			this.realmAccess = undefined;
			this.resourceAccess = undefined;
			this.authenticated = false;
		}
	}


	// --- Static Helper Methods ---
	static #createUUID(): string {
		if (typeof crypto === 'undefined' || typeof crypto.randomUUID === 'undefined') {
			throw new Error('Web Crypto API (randomUUID) is not available.');
		}
		return crypto.randomUUID();
	}
	
	static #generateRandomData(len: number): Uint8Array {
		if (typeof crypto === 'undefined' || typeof crypto.getRandomValues === 'undefined') {
			throw new Error('Web Crypto API (getRandomValues) is not available.');
		}
		return crypto.getRandomValues(new Uint8Array(len));
	}

	static #generateCodeVerifier(len: number): string {
		return Keycloak.#generateRandomString(len, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
	}

	static #generateRandomString(len: number, alphabet: string): string {
		const randomData = Keycloak.#generateRandomData(len);
		const chars = new Array(len);
		for (let i = 0; i < len; i++) {
			chars[i] = alphabet.charCodeAt(randomData[i] % alphabet.length);
		}
		return String.fromCharCode(...chars);
	}
	
	static async #generatePkceChallenge(pkceMethod: 'S256' | false, codeVerifier: string): Promise<string> {
		if (pkceMethod !== 'S256') {
			throw new TypeError(`Invalid value for 'pkceMethod', expected 'S256' but got '${pkceMethod}'.`);
		}
		const hashBytes = new Uint8Array(await sha256Digest(codeVerifier));
		return bytesToBase64(hashBytes)
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=/g, '');
	}

	static #buildClaimsParameter(requestedAcr: string): string { // This seems Keycloak specific
		const claims = { id_token: { acr: requestedAcr } };
		return JSON.stringify(claims);
	}
	
	static async #fetchJSON<T = unknown>(url: string, init: RequestInit = {}): Promise<T> {
		const headers = new Headers(init.headers);
		if (!headers.has('Accept')) {
			headers.set('Accept', CONTENT_TYPE_JSON);
		}
		
		const response = await Keycloak.#fetchWithErrorHandling(url, { ...init, headers });
		return response.json() as Promise<T>;
	}

	static async #fetchWithErrorHandling(url: string, init?: RequestInit): Promise<Response> {
		const response = await fetch(url, init);
		if (!response.ok) {
			throw new NetworkError(`Server responded with status ${response.status}`, { response, cause: init });
		}
		return response;
	}

	static #buildAuthorizationHeader(token?: string): HeadersInit {
		if (!token) {
			throw new Error('Unable to build authorization header, token is not set.');
		}
		return [['Authorization', `bearer ${token}`]];
	}

	static async #fetchJsonConfig(url: string): Promise<IJsonConfig> {
		return Keycloak.#fetchJSON<IJsonConfig>(url);
	}

	static async #fetchOpenIdConfig(url: string): Promise<IOpenIdProviderMetadata> {
		return Keycloak.#fetchJSON<IOpenIdProviderMetadata>(url);
	}
	
	// Ensure #fetchAccessToken and #fetchRefreshToken are defined as static private methods
	static async #fetchAccessToken(
		url: string,
		code: string,
		clientId: string,
		redirectUri: string,
		pkceCodeVerifier?: string,
	): Promise<IRptResponse> { // Assuming IRptResponse or similar for token response
		const body = new URLSearchParams([
			['code', code],
			['grant_type', 'authorization_code'],
			['client_id', clientId],
			['redirect_uri', redirectUri],
		]);

		if (pkceCodeVerifier) {
			body.append('code_verifier', pkceCodeVerifier);
		}

		return Keycloak.#fetchJSON<IRptResponse>(url, {
			method: 'POST',
			credentials: 'include', // Or 'same-origin' depending on requirements
			body,
		});
	}

	static async #fetchRefreshToken(
		url: string,
		refreshTokenValue: string, // Renamed to avoid conflict with instance member
		clientId: string,
	): Promise<IRptResponse> { // Assuming IRptResponse or similar for token response
		const body = new URLSearchParams([
			['grant_type', 'refresh_token'],
			['refresh_token', refreshTokenValue],
			['client_id', clientId],
		]);

		return Keycloak.#fetchJSON<IRptResponse>(url, {
			method: 'POST',
			credentials: 'include', // Or 'same-origin'
			body,
		});
	}
}


// --- Storage Implementations ---
class KeycloakLocalStorage implements ICallbackStorage {
	constructor() {
		// Test localStorage availability
		localStorage.setItem('kc-test', 'test');
		localStorage.removeItem('kc-test');
	}

	#getStoredEntries(): Array<[string, string]> {
		return Object.entries(localStorage).filter(([key]) => key.startsWith(STORAGE_KEY_PREFIX));
	}

	#parseExpiry(value: string): number | null {
		let parsedValue;
		try {
			parsedValue = JSON.parse(value);
		} catch (error) {
			return null;
		}
		if (isObject(parsedValue) && 'expires' in parsedValue && typeof parsedValue.expires === 'number') {
			return parsedValue.expires;
		}
		return null;
	}

	#clearInvalidValues(): void {
		const currentTime = Date.now();
		for (const [key, value] of this.#getStoredEntries()) {
			const expiry = this.#parseExpiry(value);
			if (expiry === null || expiry < currentTime) {
				localStorage.removeItem(key);
			}
		}
	}

	#clearAllValues(): void {
		for (const [key] of this.#getStoredEntries()) {
			localStorage.removeItem(key);
		}
	}

	public get(state: string): ICallbackStorageState | undefined {
		if (!state) return undefined;

		const key = STORAGE_KEY_PREFIX + state;
		const value = localStorage.getItem(key);
		if (value) {
			localStorage.removeItem(key);
			try {
				const parsed = JSON.parse(value) as ICallbackStorageState;
				// Quick check for essential properties before returning
				if (parsed && typeof parsed.state === 'string' && typeof parsed.nonce === 'string') {
					this.#clearInvalidValues();
					return parsed;
				}
			} catch (e) {
				// Value was not valid JSON
			}
		}
		this.#clearInvalidValues();
		return undefined;
	}

	public add(state: ICallbackStorageState): void {
		this.#clearInvalidValues();
		const key = STORAGE_KEY_PREFIX + state.state;
		const valueWithExpiry: ICallbackStorageState = {
			...state,
			expires: Date.now() + 60 * 60 * 1000, // 1 hour expiry
		};
		try {
			localStorage.setItem(key, JSON.stringify(valueWithExpiry));
		} catch (error) {
			this.#clearAllValues(); // Storage full, clear all our known entries and try again
			localStorage.setItem(key, JSON.stringify(valueWithExpiry));
		}
	}
}

class KeycloakCookieStorage implements ICallbackStorage {
	#cookieExpiration(minutes: number): Date {
		const exp = new Date();
		exp.setTime(exp.getTime() + minutes * 60 * 1000);
		return exp;
	}

	#getCookie(key: string): string {
		const name = key + '=';
		const ca = document.cookie.split(';');
		for (let c of ca) {
			c = c.trimStart();
			if (c.startsWith(name)) {
				return c.substring(name.length, c.length);
			}
		}
		return '';
	}

	#setCookie(key: string, value: string, expirationDate: Date, secure?: boolean): void {
		let cookie = `${key}=${value}; expires=${expirationDate.toUTCString()}; path=/`;
		if (secure === undefined) {
			secure = window.location.protocol === 'https:';
		}
		if (secure) {
			cookie += '; Secure';
		}
		cookie += '; SameSite=Lax'; // Recommended for modern browsers
		document.cookie = cookie;
	}

	public get(state: string): ICallbackStorageState | undefined {
		if (!state) return undefined;
		const key = STORAGE_KEY_PREFIX + state;
		const value = this.#getCookie(key);
		this.#setCookie(key, '', this.#cookieExpiration(-100)); // Delete cookie
		if (value) {
			try {
				const parsed = JSON.parse(value) as ICallbackStorageState;
				if (parsed && typeof parsed.state === 'string' && typeof parsed.nonce === 'string') {
					return parsed;
				}
			} catch (e) {
				// Not valid JSON
			}
		}
		return undefined;
	}

	public add(state: ICallbackStorageState): void {
		const key = STORAGE_KEY_PREFIX + state.state;
		// Cookies have size limits, ensure state is not excessively large
		this.#setCookie(key, JSON.stringify(state), this.#cookieExpiration(60)); // 1 hour expiry
	}

	public removeItem(key: string): void {
		this.#setCookie(key, '', this.#cookieExpiration(-100));
	}
}

export default Keycloak;

// Declarations for Cordova and Universal Links if not using @types
declare global {
	interface Window {
		Cordova?: unknown;
		cordova?: {
			InAppBrowser?: {
				open: (url: string, target: string, options: string) => ({
					addEventListener: (event: string, callback: (event: { url: string }) => void) => void;
					close: () => void;
				});
			};
			plugins?: {
				browsertab?: {
					openUrl: (url: string) => void;
					close: () => void;
				};
			};
		};
		universalLinks?: {
			subscribe: (eventName: string, callback: (event: { url: string }) => void) => void;
			unsubscribe: (eventName: string) => void;
		};
	}
}
