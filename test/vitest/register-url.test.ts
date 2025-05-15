import { describe, it, expect, beforeEach, vi } from 'vitest';
import Keycloak, { 
  type IKeycloakInitOptions, 
  type IKeycloakRegisterOptions,
  type KeycloakConfig
} from '../../lib/keycloak.ts';

// Constants
const BASE_URL = 'http://localhost:8080/auth';
const REALM = 'test-realm';
const CLIENT_ID = 'test-client';
const DEFAULT_REDIRECT_URI = 'http://localhost:3000/default-redirect';
// Based on Keycloak.ts refactor, register endpoint is realmUrl + /protocol/openid-connect/registrations
const REGISTER_ENDPOINT_PATH = `/realms/${REALM}/protocol/openid-connect/registrations`; 
const AUTH_ENDPOINT_PATH = `/realms/${REALM}/protocol/openid-connect/auth`;


interface MockWindow extends Window {
  // Add specific properties if needed
}

describe('createRegisterUrl', () => {
  let keycloak: Keycloak;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let mockWindow: MockWindow;

  beforeEach(async () => {
    mockWindow = {
      location: {
        href: DEFAULT_REDIRECT_URI,
        origin: 'http://localhost:3000',
        assign: vi.fn(),
        replace: vi.fn(),
        reload: vi.fn(),
        ancestorOrigins: [] as unknown as DOMStringList,
        protocol: 'http:',
        host: 'localhost:3000',
        hostname: 'localhost',
        pathname: '/default-redirect',
        port: '3000',
        search: '',
        hash: '',
      },
      crypto: {
        randomUUID: () => 'mocked-uuid-' + String(Math.random()).slice(2),
        getRandomValues: <T extends Uint8Array | null>(array: T): T => {
          if (array instanceof Uint8Array) {
            for (let i = 0; i < array.length; i++) array[i] = Math.floor(Math.random() * 256);
          }
          return array;
        },
        subtle: {
          digest: async (_algorithm: string, _data: Uint8Array) => new ArrayBuffer(32),
        } as SubtleCrypto,
      } as Crypto,
      history: {
        replaceState: vi.fn(),
        pushState: vi.fn(),
        go: vi.fn(),
        back: vi.fn(),
        forward: vi.fn(),
        state: null,
        length: 0,
        scrollRestoration: 'auto',
      },
      btoa: (str: string) => Buffer.from(str).toString('base64'),
      atob: (b64Encoded: string) => Buffer.from(b64Encoded, 'base64').toString(),
      document: {
        createElement: vi.fn(() => ({ 
            setAttribute: vi.fn(), 
            style: {} as CSSStyleDeclaration,
            contentWindow: { postMessage: vi.fn() } as unknown as Window,
            onload: vi.fn(),
            src: '',
        })),
        body: { 
            appendChild: vi.fn((node: Node) => node), 
            removeChild: vi.fn((node: Node) => node) 
        },
        title: 'Mock Document',
        cookie: '',
        // ... other document properties as needed
      } as unknown as Document,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      localStorage: {
        getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn(), key: vi.fn(), length: 0,
      },
      sessionStorage: {
        getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn(), key: vi.fn(), length: 0,
      },
      isSecureContext: true,
      setTimeout: vi.fn((fn: TimerHandler, _ms?: number) => typeof fn === 'function' ? 1 as unknown as number : 0 as unknown as number),
      clearTimeout: vi.fn(),
      fetch: vi.fn(),
      innerHeight: 768,
      innerWidth: 1024,
      origin: 'http://localhost:3000',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any;
    vi.stubGlobal('window', mockWindow);
    vi.stubGlobal('document', mockWindow.document);

    global.fetch = vi.fn(async (url: RequestInfo | URL) => {
      const urlString = url.toString();
      if (urlString.includes('.well-known/openid-configuration')) {
        // For createRegisterUrl, the key part is that authServerUrl and realm are set,
        // so that #getRealmUrl() works, from which the registration endpoint is derived.
        // The actual content of OIDC discovery isn't strictly needed for this specific endpoint derivation
        // if it's not a generic OIDC provider.
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({ 
            authorization_endpoint: `${BASE_URL}${AUTH_ENDPOINT_PATH}`,
            token_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/token`,
            // registration_endpoint is not typically part of standard OIDC discovery
            // Keycloak.ts derives it as: getRealmUrl() + '/protocol/openid-connect/registrations'
          }),
        } as Response);
      } else if (urlString.includes('/realms/' + REALM + '/protocol/openid-connect/3p-cookies/step1.html')) {
        return Promise.resolve({
            ok: true,
            status: 200,
            text: async () => '<html><body><script>parent.postMessage("supported", "*");</script></body></html>',
        } as Response);
      }
      return Promise.resolve({ 
        ok: false, 
        status: 404, 
        json: async () => ({ error: 'Not Found' }),
        text: async () => ('Not Found'),
      } as Response);
    });

    const keycloakConfig: KeycloakConfig = { url: BASE_URL, realm: REALM, clientId: CLIENT_ID };
    keycloak = new Keycloak(keycloakConfig);
    
    const initOptions: IKeycloakInitOptions = { pkceMethod: 'S256' }; // Enable PKCE by default
    await keycloak.init(initOptions);
  });

  it('creates a registration URL with default options', async () => {
    const registerUrlString = await keycloak.createRegisterUrl({});
    const registerUrl = new URL(registerUrlString);

    expect(registerUrl.protocol).toBe('http:');
    expect(registerUrl.host).toBe('localhost:8080'); // From BASE_URL
    // createRegisterUrl internally calls createLoginUrl with action: 'register'.
    // The endpoint used by createLoginUrl when action is 'register' is kc.endpoints.register()
    // which is `${realmUrl}/protocol/openid-connect/registrations`.
    expect(registerUrl.pathname).toBe(`/auth${REGISTER_ENDPOINT_PATH}`);
    
    expect(registerUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(registerUrl.searchParams.get('redirect_uri')).toBe(DEFAULT_REDIRECT_URI);
    expect(registerUrl.searchParams.get('response_mode')).toBe('fragment'); // Default from Keycloak instance
    expect(registerUrl.searchParams.get('response_type')).toBe('code'); // Default from Keycloak instance
    expect(registerUrl.searchParams.get('scope')).toBe('openid'); // Default scope
    
    expect(registerUrl.searchParams.get('state')).toEqual(expect.any(String));
    expect(registerUrl.searchParams.get('nonce')).toEqual(expect.any(String));
    
    // Check for PKCE parameters
    expect(registerUrl.searchParams.get('code_challenge')).toEqual(expect.any(String));
    expect(registerUrl.searchParams.get('code_challenge_method')).toBe('S256');

    // For registration, 'kc_action' should not be present as it's implied by the endpoint
    // However, createRegisterUrl calls createLoginUrl({ ...options, action: 'register' });
    // and createLoginUrl adds 'kc_action' if options.action is present AND options.action !== 'register'.
    // This means for 'register', it should NOT add kc_action.
    // The endpoint itself signifies registration.
    expect(registerUrl.searchParams.get('kc_action')).toBeNull();
  });

  it('creates a registration URL with all options', async () => {
    const specificRedirectUri = 'http://localhost:3000/specific-register-redirect';
    const registerOptions: IKeycloakRegisterOptions = {
      redirectUri: specificRedirectUri,
      prompt: 'login', // Prompt usually not used for register, but test if it passes through
      loginHint: 'newuser',
      locale: 'fr',
      scope: 'openid email profile TestScope',
      acr: 'level0', // Test with acr
      maxAge: 7200,
      // No 'action' here as it's implicit for createRegisterUrl
    };

    const registerUrlString = await keycloak.createRegisterUrl(registerOptions);
    const registerUrl = new URL(registerUrlString);

    expect(registerUrl.pathname).toBe(`/auth${REGISTER_ENDPOINT_PATH}`);
    
    expect(registerUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(registerUrl.searchParams.get('redirect_uri')).toBe(specificRedirectUri);
    expect(registerUrl.searchParams.get('prompt')).toBe('login');
    expect(registerUrl.searchParams.get('login_hint')).toBe('newuser');
    expect(registerUrl.searchParams.get('ui_locales')).toBe('fr');
    expect(registerUrl.searchParams.get('scope')).toBe('openid email profile TestScope');
    expect(registerUrl.searchParams.get('acr_values')).toBe('level0'); // Assuming acr maps to acr_values
    expect(registerUrl.searchParams.get('max_age')).toBe('7200');

    expect(registerUrl.searchParams.get('state')).toEqual(expect.any(String));
    expect(registerUrl.searchParams.get('nonce')).toEqual(expect.any(String));
    expect(registerUrl.searchParams.get('code_challenge')).toEqual(expect.any(String));
    expect(registerUrl.searchParams.get('code_challenge_method')).toBe('S256');
    
    // As before, kc_action should not be present for registration endpoint.
    expect(registerUrl.searchParams.get('kc_action')).toBeNull();
  });

  it('throws an error if Keycloak instance is configured with a generic OIDC provider', async () => {
    const genericOidcConfig: KeycloakConfig = {
      clientId: 'generic-client',
      oidcProvider: { // This makes it a generic OIDC provider
        authorization_endpoint: 'https://example.com/auth',
        token_endpoint: 'https://example.com/token',
        // No registration_endpoint defined by generic OIDC provider typically
      },
    };
    const genericKeycloak = new Keycloak(genericOidcConfig);
    await genericKeycloak.init({});

    // The Keycloak.ts refactor for `createRegisterUrl` calls `createLoginUrl`
    // which in turn calls `this.#endpoints.register()`.
    // For a generic OIDC provider, `this.#endpoints.register()` is defined to throw an error.
    await expect(genericKeycloak.createRegisterUrl({}))
      .rejects
      .toThrow('Redirection to "Register user" page not supported in standard OIDC mode.');
  });
});
