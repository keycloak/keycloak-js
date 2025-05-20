import { vi, describe, it, expect, beforeEach, afterEach, SpyInstance } from 'vitest';
import Keycloak from './cloak';
import type {
  IKeycloakAdapter,
  IKeycloakConfig,
  IKeycloakInitOptions,
  IKeycloakLoginOptions,
  IKeycloakLogoutOptions,
  KeycloakFlow,
  KeycloakOnLoad,
  KeycloakResponseMode,
  // IOpenIdProviderMetadata, // For oidcProvider mocking later
} from './types';

// --- Mocking Browser Globals & APIs ---

const mockCrypto = {
  getRandomValues: vi.fn((array: Uint8Array) => {
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
    return array;
  }),
  subtle: {
    digest: vi.fn(async (algorithm: string, data: BufferSource) => {
      if (algorithm === 'SHA-256') {
        const inputString = new TextDecoder().decode(data);
        const buf = new ArrayBuffer(32);
        const view = new Uint8Array(buf);
        for (let i = 0; i < inputString.length && i < 32; i++) {
          view[i] = inputString.charCodeAt(i);
        }
        return buf;
      }
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }),
  },
  randomUUID: vi.fn(() => 'mock-uuid-' + Math.random().toString(36).substring(2, 15)),
};

const mockLocalStorage = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => { store[key] = value; }),
    removeItem: vi.fn((key: string) => { delete store[key]; }),
    clear: vi.fn(() => { store = {}; }),
  };
})();

const mockLocation = {
  href: 'http://localhost/initial',
  origin: 'http://localhost',
  assign: vi.fn((url: string | URL) => { mockLocation.href = String(url); }),
  replace: vi.fn((url: string | URL) => { mockLocation.href = String(url); }),
};

const mockHistory = {
  replaceState: vi.fn(),
};

const mockDocument = {
  createElement: vi.fn((tagName: string) => {
    if (tagName === 'iframe') {
      const mockIframe = {
        setAttribute: vi.fn(),
        style: { display: '' } as CSSStyleDeclaration,
        onload: null as (() => void) | null,
        onerror: null as (() => void) | null,
        contentWindow: { postMessage: vi.fn() } as any,
        parentNode: { removeChild: vi.fn() } as any,
        remove: vi.fn(), // Adding remove method
      };
      // Simulate parentNode for removeChild
      Object.defineProperty(mockIframe, 'parentNode', {
        value: mockDocument.body, // Or a more specific mock parent if needed
        writable: true,
      });
      return mockIframe;
    }
    if (tagName === 'form') {
      return {
        setAttribute: vi.fn(),
        style: { display: '' },
        submit: vi.fn(),
        appendChild: vi.fn(),
        remove: vi.fn(),
      };
    }
    return { setAttribute: vi.fn(), style: {} };
  }),
  body: {
    appendChild: vi.fn((node: any) => node), // Return node for chaining if needed
    removeChild: vi.fn((node: any) => node),
  },
  cookie: '',
};

const mockBtoa = vi.fn((str: string) => Buffer.from(str).toString('base64'));
const mockAtob = vi.fn((str: string) => Buffer.from(str, 'base64').toString());

// --- Mock Keycloak Adapter ---
const mockAdapter: IKeycloakAdapter = {
  login: vi.fn(async (_options?: IKeycloakLoginOptions) => { /* console.log('mockAdapter.login called', options); */ }),
  logout: vi.fn(async (_options?: IKeycloakLogoutOptions) => { /* console.log('mockAdapter.logout called', options); */ }),
  register: vi.fn(async (_options?: IKeycloakLoginOptions) => { /* console.log('mockAdapter.register called', options); */ }),
  accountManagement: vi.fn(async () => { /* console.log('mockAdapter.accountManagement called'); */ }),
  redirectUri: vi.fn((options?: { redirectUri?: string }): string => options?.redirectUri || mockLocation.href),
};


describe('Keycloak Class', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', mockCrypto);
    vi.stubGlobal('localStorage', mockLocalStorage);
    vi.stubGlobal('location', { ...mockLocation }); // Spread to avoid issues with read-only properties
    vi.stubGlobal('document', mockDocument);
    vi.stubGlobal('history', mockHistory);
    vi.stubGlobal('fetch', vi.fn());
    vi.stubGlobal('URLSearchParams', URLSearchParams);
    vi.stubGlobal('Headers', Headers);
    vi.stubGlobal('MessageEvent', MessageEvent);
    vi.stubGlobal('setTimeout', vi.fn((fn: () => void, _ms: number) => { fn(); return 1 as unknown as NodeJS.Timeout; }));
    vi.stubGlobal('clearTimeout', vi.fn());
    vi.stubGlobal('btoa', mockBtoa);
    vi.stubGlobal('atob', mockAtob);
    vi.stubGlobal('window', {
      location: mockLocation,
      history: mockHistory,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      isSecureContext: true,
      setTimeout: global.setTimeout, // Use actual setTimeout or Vitest's fake timers
      clearTimeout: global.clearTimeout,
      document: mockDocument,
      crypto: mockCrypto,
      localStorage: mockLocalStorage,
      btoa: mockBtoa,
      atob: mockAtob,
    });

    vi.resetAllMocks(); // Reset all mocks defined with vi.fn()

    // Explicitly reset mocks that might have state or specific implementations
    mockLocalStorage.clear(); // Clear localStorage store
    mockDocument.cookie = ''; // Reset cookies
    mockLocation.href = 'http://localhost/initial'; // Reset location
    (global.fetch as SpyInstance).mockReset(); // Reset fetch if it was used with mockImplementation etc.
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  // --- Constructor and Init Tests ---
  describe('Constructor and init()', () => {
    it('should throw error for invalid config (not string or object)', () => {
      // @ts-expect-error Testing invalid config
      expect(() => new Keycloak(123)).toThrow("Config must be an object or a non-empty URL string");
    });

    it('should throw error for empty config URL string', () => {
        expect(() => new Keycloak('')).toThrow("Config URL string cannot be empty");
    });

    it('should throw error for missing required properties in config object (url, realm, clientId)', () => {
      expect(() => new Keycloak({ realm: 'test', clientId: 'test-client' } as IKeycloakConfig)).toThrow("Missing required config property 'url'");
      expect(() => new Keycloak({ url: 'http://localhost', clientId: 'test-client' } as IKeycloakConfig)).toThrow("Missing required config property 'realm'");
      expect(() => new Keycloak({ url: 'http://localhost', realm: 'test' } as IKeycloakConfig)).toThrow("Missing required config property 'clientId'");
    });
    
    it('should throw error for missing clientId in OIDC config object', () => {
        const oidcProviderConfig = { authorization_endpoint: 'http://oidc/auth', token_endpoint: 'http://oidc/token', issuer: 'http://oidc/issuer' };
        // @ts-expect-error
        expect(() => new Keycloak({ oidcProvider: oidcProviderConfig })).toThrow("Missing required config property 'clientId'");
    });

    it('should initialize with a valid string URL config', async () => {
      const configUrl = 'http://localhost/keycloak.json';
      (global.fetch as SpyInstance).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ realm: 'test', resource: 'test-client', 'auth-server-url': 'http://localhost/auth' }),
      });
      const kc = new Keycloak(configUrl);
      await kc.init({});
      expect(kc.didInitialize).toBe(true);
      expect(kc.realm).toBe('test');
      expect(kc.clientId).toBe('test-client');
      expect(kc.authServerUrl).toBe('http://localhost/auth');
    });

    it('should initialize with a valid config object', async () => {
      const config: IKeycloakConfig = { url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' };
      const kc = new Keycloak(config);
      await kc.init({});
      expect(kc.didInitialize).toBe(true);
      expect(kc.realm).toBe('test');
      expect(kc.clientId).toBe('test-client');
      expect(kc.authServerUrl).toBe('http://localhost/auth');
    });
    
    it('should initialize with OIDC provider config URL', async () => {
        (global.fetch as SpyInstance).mockResolvedValueOnce({
          ok: true,
          json: async () => ({ 
            authorization_endpoint: 'http://localhost/auth/realms/test/protocol/openid-connect/auth',
            token_endpoint: 'http://localhost/auth/realms/test/protocol/openid-connect/token',
            issuer: 'http://localhost/auth/realms/test' 
          }),
        });
        const kc = new Keycloak({ oidcProvider: 'http://localhost/auth/realms/test', clientId: 'test-client-oidc' });
        await kc.init({});
        expect(kc.didInitialize).toBe(true);
        expect(kc.clientId).toBe('test-client-oidc');
        expect(kc.endpoints.authorize()).toBe('http://localhost/auth/realms/test/protocol/openid-connect/auth');
      });
  
      it('should initialize with OIDC provider config object', async () => {
        const oidcProviderConfig = { 
            authorization_endpoint: 'http://my-oidc/auth', 
            token_endpoint: 'http://my-oidc/token',
            issuer: 'http://my-oidc' 
        };
        const kc = new Keycloak({ oidcProvider: oidcProviderConfig, clientId: 'test-client-oidc-obj' });
        await kc.init({});
        expect(kc.didInitialize).toBe(true);
        expect(kc.clientId).toBe('test-client-oidc-obj');
        expect(kc.endpoints.authorize()).toBe('http://my-oidc/auth');
      });

    it('should set loginRequired property if onLoad is "login-required"', async () => {
      const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
      kc.adapter = mockAdapter;
      await kc.init({ onLoad: 'login-required' });
      expect(kc.loginRequired).toBe(true);
      expect(mockAdapter.login).toHaveBeenCalled();
    });

    it('should correctly set flow and responseType', async () => {
      const kcStandard = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
      await kcStandard.init({ flow: 'standard' });
      expect(kcStandard.flow).toBe('standard');
      expect(kcStandard.responseType).toBe('code');

      const kcImplicit = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
      await kcImplicit.init({ flow: 'implicit' });
      expect(kcImplicit.flow).toBe('implicit');
      expect(kcImplicit.responseType).toBe('id_token token');
      
      const kcHybrid = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
      await kcHybrid.init({ flow: 'hybrid' });
      expect(kcHybrid.flow).toBe('hybrid');
      expect(kcHybrid.responseType).toBe('code id_token token');
    });

    it('should set pkceMethod correctly', async () => {
      const kcS256 = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
      await kcS256.init({ pkceMethod: 'S256' });
      expect(kcS256.pkceMethod).toBe('S256');

      const kcNoPkce = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
      await kcNoPkce.init({ pkceMethod: false });
      expect(kcNoPkce.pkceMethod).toBe(false);
    });
    
    it('should call onReady with authenticated status after init', async () => {
        const onReadyMock = vi.fn();
        const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
        kc.onReady = onReadyMock;
        await kc.init({});
        expect(onReadyMock).toHaveBeenCalledWith(false);
    });
    
    it('init() with onLoad=\'check-sso\' and login iframe enabled, session unchanged', async () => {
        const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
        kc.adapter = mockAdapter;
        const setupCheckLoginIframeSpy = vi.spyOn(kc, 'setupCheckLoginIframe').mockResolvedValueOnce();
        const checkLoginIframeSpy = vi.spyOn(kc, 'checkLoginIframe').mockResolvedValueOnce(true);

        await kc.init({ onLoad: 'check-sso', checkLoginIframe: true });

        expect(setupCheckLoginIframeSpy).toHaveBeenCalled();
        expect(checkLoginIframeSpy).toHaveBeenCalled();
        expect(kc.authenticated).toBe(false);
      });
  
      it('init() with onLoad=\'check-sso\', login iframe, session changed, silent SSO success', async () => {
        const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
        kc.adapter = mockAdapter;
        const onAuthSuccessMock = vi.fn();
        kc.onAuthSuccess = onAuthSuccessMock;
        
        vi.spyOn(kc, 'setupCheckLoginIframe').mockResolvedValueOnce();
        vi.spyOn(kc, 'checkLoginIframe').mockResolvedValueOnce(false);
        
        const mockValidSsoCallback = {
            valid: 'true', code: 'sso-code', state: 'sso-state', session_state: 'sso-session',
            newUrl: 'http://localhost/sso-callback', storedNonce: 'mock-nonce', 
            redirectUri: 'http://localhost/silent-check-sso.html',
          };
        // Mock parseCallback for the main URL (no callback) and then for the silent SSO iframe
        vi.spyOn(kc, 'parseCallback')
            .mockReturnValueOnce(undefined) // Main URL
            .mockReturnValueOnce(mockValidSsoCallback as any); // iframe URL
        
        (global.fetch as SpyInstance).mockResolvedValueOnce({
            ok: true,
            json: async () => ({ access_token: 'new-access-token', refresh_token: 'new-refresh-token', id_token: 'new-id-token' }),
        });

        await kc.init({ onLoad: 'check-sso', checkLoginIframe: true, silentCheckSsoRedirectUri: 'http://localhost/silent-check-sso.html' });
        
        expect(kc.authenticated).toBe(true);
        expect(onAuthSuccessMock).toHaveBeenCalled();
        expect(kc.token).toBe('new-access-token');
      });

      it('init() with token and refreshToken provided, login iframe enabled, session unchanged', async () => {
        const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
        kc.adapter = mockAdapter;
        const onAuthSuccessMock = vi.fn();
        kc.onAuthSuccess = onAuthSuccessMock;
        
        vi.spyOn(kc, 'setupCheckLoginIframe').mockResolvedValueOnce();
        vi.spyOn(kc, 'checkLoginIframe').mockResolvedValueOnce(true);
        vi.spyOn(kc, 'updateToken').mockResolvedValue(true);
        
        await kc.init({ token: 'initial-token', refreshToken: 'initial-refresh', checkLoginIframe: true });

        expect(kc.token).toBe('initial-token');
        expect(kc.refreshToken).toBe('initial-refresh');
        expect(kc.authenticated).toBe(true);
        expect(onAuthSuccessMock).toHaveBeenCalled();
        expect(kc.updateToken).not.toHaveBeenCalled();
      });

      it('init() with token and refreshToken provided, login iframe disabled, updateToken success', async () => {
        const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
        kc.adapter = mockAdapter;
        const onAuthSuccessMock = vi.fn();
        kc.onAuthSuccess = onAuthSuccessMock;
        
        const updateTokenSpy = vi.spyOn(kc, 'updateToken').mockImplementation(async () => {
            (kc as any).#setToken('updated-token', 'updated-refresh', 'updated-id-token', Date.now());
            return true;
        });
        
        await kc.init({ token: 'initial-token', refreshToken: 'initial-refresh', checkLoginIframe: false });

        expect(updateTokenSpy).toHaveBeenCalledWith(-1);
        expect(kc.token).toBe('updated-token');
        expect(kc.refreshToken).toBe('updated-refresh');
        expect(kc.authenticated).toBe(true);
        expect(onAuthSuccessMock).toHaveBeenCalled();
      });

      it('init() with onLoad=\'check-sso\', iframe changed, no silent URI, calls login prompt=none', async () => {
        const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
        kc.adapter = mockAdapter;
        vi.spyOn(kc, 'setupCheckLoginIframe').mockResolvedValueOnce();
        vi.spyOn(kc, 'checkLoginIframe').mockResolvedValueOnce(false); // Session changed

        await kc.init({ onLoad: 'check-sso', checkLoginIframe: true, silentCheckSsoRedirectUri: undefined });
        
        expect(mockAdapter.login).toHaveBeenCalledWith({ prompt: 'none', locale: undefined });
      });
  });

  // --- URL Creation Tests ---
  describe('URL Creation Methods', () => {
    let kcInstance: Keycloak;

    beforeEach(async () => {
      const config: IKeycloakConfig = { url: 'http://localhost:8080/auth', realm: 'myrealm', clientId: 'myclient' };
      kcInstance = new Keycloak(config);
      kcInstance.authServerUrl = config.url;
      kcInstance.realm = config.realm;
      kcInstance.clientId = config.clientId;
      kcInstance.endpoints = (kcInstance as any).#defaultEndpoints();
      kcInstance.adapter = mockAdapter;
    });

    it('createLoginUrl() should create a basic login URL', async () => {
      const loginUrl = await kcInstance.createLoginUrl();
      expect(loginUrl).toContain('http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/auth');
      expect(loginUrl).toContain('client_id=myclient');
      expect(loginUrl).toContain('response_mode=fragment');
      expect(loginUrl).toContain('response_type=code');
      expect(loginUrl).toContain('scope=openid');
      expect(loginUrl).toMatch(/state=[a-f0-9-]+/);
      expect(loginUrl).toMatch(/nonce=[a-f0-9-]+/);
      expect(loginUrl).toMatch(/code_challenge=/);
      expect(loginUrl).toContain('code_challenge_method=S256');
    });

    it('createLoginUrl() with various options', async () => {
      const options: IKeycloakLoginOptions = {
        redirectUri: 'http://localhost/custom-redirect', prompt: 'login', scope: 'email profile custom_scope',
        locale: 'fr', loginHint: 'testuser', idpHint: 'my-idp', action: 'register', maxAge: 3600,
      };
      kcInstance.scope = 'openid profile';

      const loginUrl = await kcInstance.createLoginUrl(options);

      expect(loginUrl).toContain(kcInstance.endpoints.register());
      expect(loginUrl).toContain('redirect_uri=' + encodeURIComponent(options.redirectUri!));
      expect(loginUrl).toContain('prompt=login');
      expect(loginUrl).toContain('scope=' + encodeURIComponent('openid email profile custom_scope'));
      expect(loginUrl).toContain('ui_locales=fr');
      expect(loginUrl).toContain('login_hint=testuser');
      expect(loginUrl).toContain('kc_idp_hint=my-idp');
      expect(loginUrl).toContain('max_age=3600');
      expect(loginUrl).not.toContain('kc_action=register'); 
    });
    
    it('createLoginUrl() without PKCE if pkceMethod is false', async () => {
      kcInstance.pkceMethod = false;
      const loginUrl = await kcInstance.createLoginUrl();
      expect(loginUrl).not.toContain('code_challenge=');
      expect(loginUrl).not.toContain('code_challenge_method=');
    });

    it('createLogoutUrl() should create basic logout URL without idToken', () => {
        kcInstance.idToken = undefined;
        const logoutUrl = kcInstance.createLogoutUrl();
        expect(logoutUrl).toContain('http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/logout');
        expect(logoutUrl).toContain('client_id=myclient');
        expect(logoutUrl).not.toContain('id_token_hint=');
        expect(logoutUrl).toContain('post_logout_redirect_uri=' + encodeURIComponent(mockLocation.href));
      });
  
      it('createLogoutUrl() should include id_token_hint if idToken is present', () => {
        kcInstance.idToken = 'test-id-token';
        const logoutUrl = kcInstance.createLogoutUrl();
        expect(logoutUrl).toContain('id_token_hint=test-id-token');
        expect(logoutUrl).toContain('post_logout_redirect_uri=' + encodeURIComponent(mockLocation.href));
        expect(logoutUrl).toContain('client_id=myclient');
      });
  
      it('createLogoutUrl() with custom redirectUri', () => {
        kcInstance.idToken = 'test-id-token';
        const customRedirect = 'http://localhost/logged-out';
        const logoutUrl = kcInstance.createLogoutUrl({ redirectUri: customRedirect });
        expect(logoutUrl).toContain('post_logout_redirect_uri=' + encodeURIComponent(customRedirect));
      });
      
      it('createLogoutUrl() for POST method should just return the endpoint', () => {
        kcInstance.logoutMethod = 'POST';
        const logoutUrl = kcInstance.createLogoutUrl();
        expect(logoutUrl).toBe('http://localhost:8080/auth/realms/myrealm/protocol/openid-connect/logout');
      });

    it('createRegisterUrl() should call createLoginUrl with action "register"', async () => {
        const createLoginUrlSpy = vi.spyOn(kcInstance, 'createLoginUrl');
        const options = { scope: 'email' };
        await kcInstance.createRegisterUrl(options);
        expect(createLoginUrlSpy).toHaveBeenCalledWith({ ...options, action: 'register' });
      });
  
    it('createAccountUrl() should create the account management URL', () => {
        const accountUrl = kcInstance.createAccountUrl();
        expect(accountUrl).toContain('http://localhost:8080/auth/realms/myrealm/account');
        expect(accountUrl).toContain('referrer=myclient');
        expect(accountUrl).toContain('referrer_uri=' + encodeURIComponent(mockLocation.href));
    });

    it('createAccountUrl() should return undefined if realm URL cannot be determined', () => {
        const originalGetRealmUrl = (kcInstance as any).#getRealmUrl;
        (kcInstance as any).#getRealmUrl = () => undefined; 
        const accountUrl = kcInstance.createAccountUrl();
        expect(accountUrl).toBeUndefined();
        (kcInstance as any).#getRealmUrl = originalGetRealmUrl;
    });
  });
  
  // --- Token Methods Tests ---
  describe('Token Methods', () => {
    let kcInstance: Keycloak;
    const mockValidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MDAwMDAwMDAsInNpZCI6InNvbWUtc2Vzc2lvbi1pZCIsIm5vbmNlIjoibW9jay1ub25jZSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1c2VyIl19fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const mockExpiredToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleHBpcmVkIiwibmFtZSI6IkV4cGlyZWQgVXNlciIsImlhdCI6MTQxNjIzOTAyMiwiZXhwIjoxNTE2MjM5MDIyLCJzaWQiOiJleHBpcmVkLXNlc3Npb24taWQiLCJub25jZSI6ImV4cGlyZWQtbm9uY2UifQ.123";

    beforeEach(async () => {
      const config: IKeycloakConfig = { url: 'http://localhost:8080/auth', realm: 'myrealm', clientId: 'myclient' };
      kcInstance = new Keycloak(config);
      kcInstance.didInitialize = true; 
      kcInstance.authServerUrl = config.url;
      kcInstance.realm = config.realm;
      kcInstance.clientId = config.clientId;
      kcInstance.endpoints = (kcInstance as any).#defaultEndpoints();
      kcInstance.adapter = mockAdapter;
      kcInstance.timeSkew = 0;
    });

    it('#setToken should parse and set token properties correctly', () => {
        const timeLocal = Date.now();
        (kcInstance as any).#setToken(mockValidToken, 'refresh-token-data', 'id-token-data', timeLocal);

        expect(kcInstance.token).toBe(mockValidToken);
        expect(kcInstance.tokenParsed).toBeDefined();
        expect(kcInstance.tokenParsed?.sub).toBe("1234567890");
        expect(kcInstance.refreshToken).toBe('refresh-token-data');
        expect(kcInstance.refreshTokenParsed).toBeDefined();
        expect(kcInstance.idToken).toBe('id-token-data');
        expect(kcInstance.idTokenParsed).toBeDefined();
        expect(kcInstance.authenticated).toBe(true);
        expect(kcInstance.sessionId).toBe("some-session-id");
        expect(kcInstance.timeSkew).toBeCloseTo(Math.floor(timeLocal / 1000) - 1516239022, 0);
      });

    it('#setToken should schedule onTokenExpired if handler is present', () => {
        const onTokenExpiredMock = vi.fn();
        kcInstance.onTokenExpired = onTokenExpiredMock;
        const setTimeoutSpy = vi.spyOn(global, 'setTimeout');

        (kcInstance as any).#setToken(mockValidToken, undefined, undefined, Date.now());
        
        expect(setTimeoutSpy).toHaveBeenCalled();
        setTimeoutSpy.mockRestore();
      });

    it('clearToken() should clear all token properties and call onAuthLogout', () => {
        (kcInstance as any).#setToken(mockValidToken, 'refresh', 'id', Date.now());
        const onAuthLogoutMock = vi.fn();
        kcInstance.onAuthLogout = onAuthLogoutMock;

        kcInstance.clearToken();

        expect(kcInstance.token).toBeUndefined();
        expect(kcInstance.tokenParsed).toBeUndefined();
        expect(kcInstance.refreshToken).toBeUndefined();
        expect(kcInstance.refreshTokenParsed).toBeUndefined();
        expect(kcInstance.idToken).toBeUndefined();
        expect(kcInstance.idTokenParsed).toBeUndefined();
        expect(kcInstance.authenticated).toBe(false);
        expect(kcInstance.sessionId).toBeUndefined();
        expect(onAuthLogoutMock).toHaveBeenCalled();
      });

    it('clearToken() should call login if loginRequired is true', () => {
        (kcInstance as any).#setToken(mockValidToken, 'refresh', 'id', Date.now());
        kcInstance.loginRequired = true;

        kcInstance.clearToken();
        expect(mockAdapter.login).toHaveBeenCalled();
    });

    it('isTokenExpired() should return true for an expired token', () => {
        (kcInstance as any).#setToken(mockExpiredToken);
        kcInstance.timeSkew = 0;
        expect(kcInstance.isTokenExpired(0)).toBe(true);
      });
  
    it('isTokenExpired() should return false for a valid token', () => {
        (kcInstance as any).#setToken(mockValidToken);
        kcInstance.timeSkew = 0;
        if(kcInstance.tokenParsed) kcInstance.tokenParsed.exp = Math.floor(Date.now() / 1000) + 300;
        expect(kcInstance.isTokenExpired(0)).toBe(false);
    });

    it('isTokenExpired() should respect minValidity', () => {
        (kcInstance as any).#setToken(mockValidToken);
        kcInstance.timeSkew = 0;
        if(kcInstance.tokenParsed) kcInstance.tokenParsed.exp = Math.floor(Date.now() / 1000) + 10;
        
        expect(kcInstance.isTokenExpired(5)).toBe(false);
        expect(kcInstance.isTokenExpired(15)).toBe(true);
    });

    it('isTokenExpired() should return true if no token is parsed', () => {
        kcInstance.tokenParsed = undefined;
        expect(kcInstance.isTokenExpired()).toBe(true);
    });
    
    it('isTokenExpired() should return true if timeSkew is undefined', () => {
        (kcInstance as any).#setToken(mockValidToken);
        kcInstance.timeSkew = undefined;
        expect(kcInstance.isTokenExpired(0)).toBe(true);
    });
  });
  
  describe('updateToken() - Edge Cases', () => {
    let kcInstance: Keycloak;
    const initialAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MSIsImV4cCI6MTcwMDAwMDAwMCwiaWF0IjoxNjk5OTk2NDAwfQ.abc";
    const initialRefreshToken = "initial-refresh-token";
    const newAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0MSIsImV4cCI6MTcwMDAwMzYwMCwiaWF0IjoxNzAwMDAwMDAwfQ.def";
    const newRefreshToken = "new-refresh-token";

    beforeEach(async () => {
        const config: IKeycloakConfig = { url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' };
        kcInstance = new Keycloak(config);
        kcInstance.didInitialize = true;
        kcInstance.authServerUrl = config.url;
        kcInstance.realm = config.realm;
        kcInstance.clientId = config.clientId;
        kcInstance.endpoints = (kcInstance as any).#defaultEndpoints();
        kcInstance.adapter = mockAdapter;
        kcInstance.timeSkew = 0;
         // Set initial tokens to be already expired for some tests
        (kcInstance as any).#setToken(initialAccessToken, initialRefreshToken, undefined, Date.now() - 3600 * 1000);
    });

    it('should return false if no refreshToken is available', async () => {
        kcInstance.refreshToken = undefined;
        const result = await kcInstance.updateToken(5);
        expect(result).toBe(false);
    });

    it('should proceed with refresh even if loginIframe is enabled and token is expired', async () => {
        kcInstance.loginIframe.enable = true;

        (global.fetch as SpyInstance).mockResolvedValueOnce({
            ok: true,
            json: async () => ({ access_token: newAccessToken, refresh_token: newRefreshToken }),
          });
        const onAuthRefreshSuccessMock = vi.fn();
        kcInstance.onAuthRefreshSuccess = onAuthRefreshSuccessMock;
        
        const result = await kcInstance.updateToken(0);

        expect(result).toBe(true);
        expect(onAuthRefreshSuccessMock).toHaveBeenCalled();
        expect(kcInstance.token).toBe(newAccessToken);
    });
  });

  // --- Callback Parsing Tests ---
  describe('Callback Parsing', () => {
    let kcInstance: Keycloak;
    const mockBaseUrl = 'http://localhost/app';

    beforeEach(async () => {
      const config: IKeycloakConfig = { url: 'http://localhost:8080/auth', realm: 'myrealm', clientId: 'myclient' };
      kcInstance = new Keycloak(config);
      kcInstance.didInitialize = true;
      kcInstance.authServerUrl = config.url;
      kcInstance.realm = config.realm;
      kcInstance.clientId = config.clientId;
      kcInstance.endpoints = (kcInstance as any).#defaultEndpoints();
      kcInstance.adapter = mockAdapter;
      kcInstance.responseMode = 'fragment';
      kcInstance.flow = 'standard';
    });

    it('parseCallbackUrl() should parse standard flow callback URL with fragment', () => {
      const url = `${mockBaseUrl}#state=test-state&session_state=test-session&code=test-code`;
      kcInstance.responseMode = 'fragment';
      kcInstance.flow = 'standard'; 
      const result = kcInstance.parseCallbackUrl(url);
      expect(result).toBeDefined();
      expect(result?.state).toBe('test-state');
      expect(result?.code).toBe('test-code');
      expect(result?.newUrl).toBe(mockBaseUrl);
    });

    it('parseCallbackUrl() should parse standard flow callback URL with query', () => {
        const url = `${mockBaseUrl}?state=test-state&session_state=test-session&code=test-code`;
        kcInstance.responseMode = 'query';
        kcInstance.flow = 'standard'; 
        const result = kcInstance.parseCallbackUrl(url);
        expect(result).toBeDefined();
        expect(result?.state).toBe('test-state');
        expect(result?.code).toBe('test-code');
        expect(result?.newUrl).toBe(mockBaseUrl);
      });

    it('parseCallbackUrl() should parse implicit flow callback URL with fragment', () => {
      const url = `${mockBaseUrl}#state=test-state&access_token=acc-token&id_token=id-tok&expires_in=300`;
      kcInstance.responseMode = 'fragment';
      kcInstance.flow = 'implicit';
      const result = kcInstance.parseCallbackUrl(url);
      expect(result).toBeDefined();
      expect(result?.state).toBe('test-state');
      expect(result?.access_token).toBe('acc-token');
      expect(result?.id_token).toBe('id-tok');
      expect(result?.newUrl).toBe(mockBaseUrl);
    });
    
    it('parseCallbackUrl() should return undefined for URL without state', () => {
        const url = `${mockBaseUrl}#code=test-code`;
        const result = kcInstance.parseCallbackUrl(url);
        expect(result).toBeUndefined();
    });

    it('parseCallback() should merge stored state with URL params', () => {
        const state = 'unique-state-123';
        const nonce = 'unique-nonce-456';
        const pkceCodeVerifier = 'pkce-verifier-789';
        const redirectUri = 'http://localhost/app/redirect';
        const loginOptions = { scope: 'openid profile' };
        
        (kcInstance as any).#callbackStorage.add({ 
            state, nonce, redirectUri: encodeURIComponent(redirectUri), pkceCodeVerifier, loginOptions
        });
        
        const callbackUrl = `${mockBaseUrl}#state=${state}&code=auth-code&session_state=session-state-abc`;
        kcInstance.responseMode = 'fragment';
        kcInstance.flow = 'standard';
        
        const parsed = kcInstance.parseCallback(callbackUrl);
        
        expect(parsed).toBeDefined();
        expect(parsed?.valid).toBe('true');
        expect(parsed?.state).toBe(state);
        expect(parsed?.code).toBe('auth-code');
        expect(parsed?.storedNonce).toBe(nonce);
        expect(parsed?.pkceCodeVerifier).toBe(pkceCodeVerifier);
        expect(parsed?.redirectUri).toBe(redirectUri);
        expect(JSON.parse(parsed?.loginOptions as string)).toEqual(loginOptions);
        expect(parsed?.newUrl).toBe(mockBaseUrl); 
      });

      it('parseCallback() should return undefined if no stored state matches URL state', () => {
        const callbackUrl = `${mockBaseUrl}#state=non-existent-state&code=auth-code`;
        const parsed = kcInstance.parseCallback(callbackUrl);
        expect(parsed).toBeUndefined();
      });
  });

  // --- More init() tests focusing on callback handling and specific scenarios ---
  describe('init() - Callback Processing and specific scenarios', () => {
    let kc: Keycloak;
    const config: IKeycloakConfig = { url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' };
    
    beforeEach(() => {
        kc = new Keycloak(config);
        kc.adapter = mockAdapter;
        (kc as any).#loadConfig = vi.fn(async () => {
            kc.authServerUrl = config.url;
            kc.realm = config.realm;
            kc.clientId = config.clientId;
            kc.endpoints = (kc as any).#defaultEndpoints();
        });
        vi.spyOn(kc, 'check3pCookiesSupported').mockResolvedValueOnce();
    });

    it('init() process valid callback with nonce mismatch, should reject and call onAuthError', async () => {
        const mockCode = 'auth-code-nonce-mismatch';
        const mockState = 'state-nonce-mismatch';
        const storedNonce = 'correct-nonce';
        const incomingNonce = 'wrong-nonce'; 
        const mockRedirectUri = 'http://localhost/app';
        
        mockLocation.href = `http://localhost/app#state=${mockState}&code=${mockCode}`;
        
        const mockParsedCallback = {
            valid: 'true', code: mockCode, state: mockState, 
            storedNonce: storedNonce, 
            redirectUri: mockRedirectUri, newUrl: 'http://localhost/app',
            pkceCodeVerifier: 'mock-pkce-verifier'
        };
        vi.spyOn(kc, 'parseCallback').mockReturnValueOnce(mockParsedCallback as any);
        vi.spyOn(kc, 'setupCheckLoginIframe').mockResolvedValueOnce();
        
        (global.fetch as SpyInstance).mockResolvedValueOnce({
            ok: true,
            json: async () => ({ 
                access_token: 'access-token', 
                refresh_token: 'refresh-token', 
                id_token: `header.${btoa(JSON.stringify({ sub: 'test', nonce: incomingNonce }))}.signature`
            }),
        });
        
        const onAuthErrorMock = vi.fn();
        kc.onAuthError = onAuthErrorMock;

        await expect(kc.init({})).rejects.toThrow('Invalid nonce.');
        
        expect(kc.authenticated).toBe(false);
        expect(onAuthErrorMock).toHaveBeenCalledWith(expect.objectContaining({ error: 'invalid_nonce' }));
    });


    it('init() with pkceMethod=false should not add PKCE params to login URL', async () => {
        kc.adapter = mockAdapter; 
        await kc.init({ pkceMethod: false, onLoad: 'login-required' }); 
        
        const loginUrl = await kc.createLoginUrl(); 
        
        expect(kc.pkceMethod).toBe(false);
        expect(loginUrl).not.toContain('code_challenge=');
        expect(loginUrl).not.toContain('code_challenge_method=');
    });

    it('init() with onLoad=\'check-sso\', loginIframe disabled, silentCheckSsoRedirectUri set, success', async () => {
        kc.silentCheckSsoRedirectUri = 'http://localhost/silent-sso.html';
        const onAuthSuccessMock = vi.fn();
        kc.onAuthSuccess = onAuthSuccessMock;

        vi.spyOn(kc, 'parseCallback').mockImplementationOnce((urlToParse): any => {
            if (urlToParse.startsWith(kc.silentCheckSsoRedirectUri!)) { 
                return { valid: 'true', code: 'sso-code', state: 'sso-state-from-iframe', storedNonce: 'nonce-from-iframe', redirectUri: kc.silentCheckSsoRedirectUri, newUrl: kc.silentCheckSsoRedirectUri };
            }
            return undefined; 
        });
        
        (global.fetch as SpyInstance).mockResolvedValueOnce({ 
            ok: true,
            json: async () => ({ access_token: 'sso-token', refresh_token: 'sso-refresh', id_token: 'sso-id' }),
        });
        
        await kc.init({ onLoad: 'check-sso', checkLoginIframe: false });

        expect(onAuthSuccessMock).toHaveBeenCalled();
        expect(kc.authenticated).toBe(true);
        expect(kc.token).toBe('sso-token');
    });
    
    it('init() with onLoad=\'check-sso\', iframe changed, no silent URI, calls login prompt=none', async () => {
        kc.adapter = mockAdapter; 
        vi.spyOn(kc, 'setupCheckLoginIframe').mockResolvedValueOnce();
        vi.spyOn(kc, 'checkLoginIframe').mockResolvedValueOnce(false); 

        await kc.init({ onLoad: 'check-sso', checkLoginIframe: true, silentCheckSsoRedirectUri: undefined });
        
        expect(mockAdapter.login).toHaveBeenCalledWith({ prompt: 'none', locale: undefined });
      });

    it('init() failure during #loadConfig', async () => {
        (kc as any).#loadConfig = vi.fn().mockRejectedValueOnce(new Error('Config load failed'));
        const onAuthErrorMock = vi.fn();
        kc.onAuthError = onAuthErrorMock;
        const onReadyMock = vi.fn();
        kc.onReady = onReadyMock;

        await expect(kc.init({})).rejects.toThrow('Config load failed');
        expect(kc.didInitialize).toBe(false);
        expect(onAuthErrorMock).toHaveBeenCalledWith(expect.any(Error));
        expect(onReadyMock).toHaveBeenCalledWith(false);
    });

    it('init() with token/refreshToken, updateToken fails, calls onAuthError and proceeds with onLoad', async () => {
        const initialToken = "old-access-token";
        const initialRefreshToken = "old-refresh-token";
        const onAuthErrorMock = vi.fn();
        kc.onAuthError = onAuthErrorMock;
        const loginAdapterSpy = vi.spyOn(mockAdapter, 'login');
    
        vi.spyOn(kc, 'updateToken').mockRejectedValueOnce(new Error("Token refresh failed"));
    
        await kc.init({ 
            token: initialToken, 
            refreshToken: initialRefreshToken, 
            checkLoginIframe: false, // simplify by disabling iframe check
            onLoad: 'login-required' 
        });
    
        expect(kc.token).toBe(initialToken); // Still old token
        expect(onAuthErrorMock).toHaveBeenCalledWith(expect.any(Error));
        expect(loginAdapterSpy).toHaveBeenCalled(); // onLoad: 'login-required' should still be triggered
        expect(kc.authenticated).toBe(true); // Authenticated with old token initially
    });

  });

  // --- #processCallback specific error/condition tests (indirectly via init) ---
  describe('#processCallback error/condition handling (via init)', () => {
    let kc: Keycloak;
    const config: IKeycloakConfig = { url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' };

    beforeEach(() => {
        kc = new Keycloak(config);
        kc.adapter = mockAdapter;
        (kc as any).#loadConfig = vi.fn(async () => {
            kc.authServerUrl = config.url; kc.realm = config.realm; kc.clientId = config.clientId;
            kc.endpoints = (kc as any).#defaultEndpoints();
        });
        vi.spyOn(kc, 'check3pCookiesSupported').mockResolvedValueOnce();
        vi.spyOn(kc, 'setupCheckLoginIframe').mockResolvedValue();
    });

    it('#processCallback: error with prompt !== "none" (not auth_expired) should call onAuthError and reject', async () => {
        mockLocation.href = `http://localhost/app#state=errState&error=login_failed&error_description=User%20not%20found`;
        const mockParsedCb = {
            valid: 'true', state: 'errState', error: 'login_failed', error_description: 'User not found', prompt: 'login',
            newUrl: 'http://localhost/app', redirectUri: 'http://localhost/app'
        };
        vi.spyOn(kc, 'parseCallback').mockReturnValueOnce(mockParsedCb as any);
        const onAuthErrorMock = vi.fn();
        kc.onAuthError = onAuthErrorMock;

        await expect(kc.init({})).rejects.toEqual(expect.objectContaining({ error: 'login_failed' }));
        expect(onAuthErrorMock).toHaveBeenCalledWith(expect.objectContaining({ error: 'login_failed', error_description: 'User not found' }));
    });
    
    it('#processCallback: error with prompt === "none" should resolve silently', async () => {
        mockLocation.href = `http://localhost/app#state=errStateNone&error=interaction_required`;
        const mockParsedCb = {
            valid: 'true', state: 'errStateNone', error: 'interaction_required', prompt: 'none',
            newUrl: 'http://localhost/app', redirectUri: 'http://localhost/app'
        };
        vi.spyOn(kc, 'parseCallback').mockReturnValueOnce(mockParsedCb as any);
        const onAuthErrorMock = vi.fn();
        kc.onAuthError = onAuthErrorMock;

        await kc.init({});
        expect(kc.authenticated).toBe(false);
        expect(onAuthErrorMock).not.toHaveBeenCalled();
    });
  });


  // --- setupCheckLoginIframe error path ---
  describe('setupCheckLoginIframe error handling', () => {
    const baseConfig: IKeycloakConfig = { url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' };
    
    it('should reject if endpoints.authorize() throws', async () => {
        const kc = new Keycloak(baseConfig);
        (kc as any).#loadConfig = vi.fn(async () => {
            kc.authServerUrl = baseConfig.url; kc.realm = baseConfig.realm; kc.clientId = baseConfig.clientId;
            kc.endpoints = { 
                authorize: () => { throw new Error('Auth endpoint error'); },
                checkSessionIframe: () => 'http://localhost/check-session.html'
            } as any;
        });
        await (kc as any).#loadConfig();
        kc.loginIframe.enable = true;
        (kc as any).loginIframe.iframe = undefined;

        await expect(kc.setupCheckLoginIframe()).rejects.toThrow('Failed to determine login iframe origin: Auth endpoint error');
    });

    it('should reject if endpoints.checkSessionIframe() throws and iframe load fails', async () => {
        const kc = new Keycloak(baseConfig);
        (kc as any).#loadConfig = vi.fn(async () => {
            kc.authServerUrl = baseConfig.url; kc.realm = baseConfig.realm; kc.clientId = baseConfig.clientId;
            kc.endpoints = { 
                authorize: () => 'http://localhost/auth/realms/test/protocol/openid-connect/auth',
                checkSessionIframe: () => { throw new Error('Check session iframe endpoint error'); } 
            } as any;
        });
        await (kc as any).#loadConfig();
        kc.loginIframe.enable = true;
        (kc as any).loginIframe.iframe = undefined;
        
        // Simulate that the error from endpoint.checkSessionIframe leads to iframe.onerror
        const mockIframe = { 
            setAttribute: vi.fn((attr: string, val: string) => { if(attr === 'src' && val.includes('error')) throw new Error('Simulated src error'); }), 
            style: {}, onload: null as any, onerror: null as any, contentWindow: null, parentNode: mockDocument.body, remove: vi.fn()
        };
        (mockDocument.createElement as SpyInstance).mockReturnValueOnce(mockIframe);
        
        // The actual error comes from iframe.onerror being triggered
        await expect(kc.setupCheckLoginIframe()).rejects.toThrow('Failed to load login status iframe.');
    });
  });


  // --- check3pCookiesSupported failure ---
  describe('check3pCookiesSupported failure/edge cases', () => {
    const baseConfig: IKeycloakConfig = { url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' };

    it('should resolve gracefully and log if thirdPartyCookiesIframe endpoint throws', async () => {
        const kc = new Keycloak(baseConfig);
        const consoleWarnSpy = vi.spyOn(console, 'warn');

        (kc as any).#loadConfig = vi.fn(async () => {
            kc.authServerUrl = baseConfig.url; kc.realm = baseConfig.realm; kc.clientId = baseConfig.clientId;
            kc.endpoints = (kc as any).#defaultEndpoints();
            kc.endpoints.thirdPartyCookiesIframe = () => { throw new Error('Not supported in OIDC mode'); };
        });
        await (kc as any).#loadConfig();
        kc.loginIframe.enable = true;
        kc.enableLogging = true;

        await expect(kc.check3pCookiesSupported()).resolves.toBeUndefined();
        expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Third-party cookie check iframe endpoint not available.'));
        consoleWarnSpy.mockRestore();
    });

    it('should handle timeout for 3p cookie check', async () => {
        vi.useFakeTimers();
        const kc = new Keycloak(baseConfig);
        const consoleWarnSpy = vi.spyOn(console, 'warn');

        (kc as any).#loadConfig = vi.fn(async () => {
            kc.authServerUrl = baseConfig.url; kc.realm = baseConfig.realm; kc.clientId = baseConfig.clientId;
            kc.endpoints = (kc as any).#defaultEndpoints();
        });
        await (kc as any).#loadConfig();
        kc.loginIframe.enable = true;
        kc.enableLogging = true;
        kc.messageReceiveTimeout = 100;

        const promise = kc.check3pCookiesSupported();
        vi.advanceTimersByTime(150);
        await expect(promise).resolves.toBeUndefined();
        expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('[KEYCLOAK] 3p cookie check timed out.'));
        
        consoleWarnSpy.mockRestore();
        vi.useRealTimers();
    });
  });

  // --- Testing onActionUpdate event handler ---
  describe('onActionUpdate event', () => {
    it('should be called from #processCallback if kc_action_status is present', async () => {
        const kc = new Keycloak({ url: 'http://localhost/auth', realm: 'test', clientId: 'test-client' });
        await (kc as any).#loadConfig(); 
        kc.adapter = mockAdapter;

        const onActionUpdateMock = vi.fn();
        kc.onActionUpdate = onActionUpdateMock;

        const oauthParams = {
            kc_action_status: 'updated',
            kc_action: 'UPDATE_PROFILE',
            error: 'some_error', prompt: 'none', state: 'test-state',
            valid: 'true', newUrl: 'http://localhost/app', redirectUri: 'http://localhost/app'
        };
        
        await (kc as any).#processCallback(oauthParams, vi.fn(), vi.fn());

        expect(onActionUpdateMock).toHaveBeenCalledWith('updated', 'UPDATE_PROFILE');
    });
  });

});
>>>>>>> REPLACE
