import { describe, it, expect, beforeEach, vi } from 'vitest';
import Keycloak, { type IKeycloakInitOptions, type IKeycloakLoginOptions } from '../../lib/keycloak.ts'; // Points to TS source

// Constants
const BASE_URL = 'http://localhost:8080/auth';
const REALM = 'test-realm';
const CLIENT_ID = 'test-client';
const DEFAULT_REDIRECT_URI = 'http://localhost:3000/default-redirect';

interface MockWindow extends Window {
  // Add specific properties if needed for stricter typing, though Vitest's stubGlobal is quite flexible
}

describe('createLoginUrl', () => {
  let keycloak: Keycloak;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let mockWindow: MockWindow; // Keep track of the mock window if direct manipulation is needed later

  beforeEach(async () => {
    // Mock window and globals
    mockWindow = {
      location: {
        href: DEFAULT_REDIRECT_URI,
        origin: 'http://localhost:3000',
        search: '', // Ensure search is present
        hash: '', // Ensure hash is present
        assign: vi.fn(),
        replace: vi.fn(),
        reload: vi.fn(),
        ancestorOrigins: [] as unknown as DOMStringList, 
        protocol: 'http:',
        host: 'localhost:3000',
        hostname: 'localhost',
        pathname: '/default-redirect',
        port: '3000',
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
          // Returns an ArrayBuffer of SHA-256's length (32 bytes)
          digest: async (_algorithm: string, _data: Uint8Array) => new ArrayBuffer(32),
        } as SubtleCrypto, // Cast to SubtleCrypto
      } as Crypto, // Cast to Crypto
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
          style: {} as CSSStyleDeclaration, // Basic style object
          contentWindow: { postMessage: vi.fn() } as unknown as Window, // For iframe postMessage
          onload: vi.fn(), // For iframe onload
          src: '',
        })),
        body: { 
          appendChild: vi.fn((node: Node) => node), 
          removeChild: vi.fn((node: Node) => node) 
        },
        // Add other document properties if Keycloak interacts with them
        title: 'Mock Document',
        cookie: '',
        documentElement: {} as HTMLElement,
        activeElement: null,
        readyState: 'complete',
        head: { appendChild: vi.fn() } as unknown as HTMLHeadElement,
        defaultView: window, // points to the global window
        createEvent: vi.fn(),
        getElementById: vi.fn(),
        getElementsByTagName: vi.fn(),
        getElementsByClassName: vi.fn(),
        querySelector: vi.fn(),
        querySelectorAll: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
        hasChildNodes: vi.fn(),
        insertBefore: vi.fn(),
        replaceChild: vi.fn(),
        contains: vi.fn(),
        getRootNode: vi.fn(),
        cloneNode: vi.fn(),
        importNode: vi.fn(),
        adoptNode: vi.fn(),
        createAttribute: vi.fn(),
        createComment: vi.fn(),
        createDocumentFragment: vi.fn(),
        createTextNode: vi.fn(),
        createRange: vi.fn(),
        hasFocus: vi.fn(),
        getSelection: vi.fn(),
        elementFromPoint: vi.fn(),
        elementsFromPoint: vi.fn(),
        append: vi.fn(),
        prepend: vi.fn(),
        replaceChildren: vi.fn(),
        fonts: {} as FontFaceSet,
        images: {} as HTMLCollectionOf<HTMLImageElement>,
        links: {} as HTMLCollectionOf<HTMLLinkElement | HTMLAreaElement>,
        scripts: {} as HTMLCollectionOf<HTMLScriptElement>,
        styleSheets: {} as StyleSheetList,
        getAnimations: vi.fn(),
        onvisibilitychange: null,
        onfullscreenchange: null,
        onfullscreenerror: null,
        exitFullscreen: vi.fn(),
        exitPictureInPicture: vi.fn(),
        getElementsByName: vi.fn(),
        open: vi.fn(),
        close: vi.fn(),
        write: vi.fn(),
        writeln: vi.fn(),
        execCommand: vi.fn(),
        queryCommandEnabled: vi.fn(),
        queryCommandIndeterm: vi.fn(),
        queryCommandState: vi.fn(),
        queryCommandSupported: vi.fn(),
        queryCommandValue: vi.fn(),
        hidden: false,
        visibilityState: 'visible',
        pictureInPictureElement: null,
        pictureInPictureEnabled: true,
        fullscreenElement: null,
        fullscreenEnabled: true,
        pointerLockElement: null,
        styleSheetsApplied: true,
        caretPositionFromPoint: vi.fn(),
        releaseCapture: vi.fn(),
        clear: vi.fn(),
        captureEvents: vi.fn(),
        releaseEvents: vi.fn(),
        all: {} as HTMLAllCollection,
        anchors: {} as HTMLCollectionOf<HTMLAnchorElement>,
        applets: {} as HTMLCollection,
        bodyUsed: false,
        characterSet: 'UTF-8',
        charset: 'UTF-8',
        compatMode: 'CSS1Compat',
        contentType: 'text/html',
        cookieEnabled: true,
        currentScript: null,
        designMode: 'off',
        dir: 'ltr',
        doctype: null,
        domain: 'localhost',
        embeds: {} as HTMLCollectionOf<HTMLEmbedElement>,
        fgColor: '#000000',
        forms: {} as HTMLCollectionOf<HTMLFormElement>,
        fullscreen: false,
        lastModified: new Date().toString(),
        linkColor: '#0000ee',
        plugins: {} as HTMLCollectionOf<HTMLEmbedElement>,
        referrer: '',
        URL: 'http://localhost:3000/default-redirect',
        alinkColor: '#ff0000',
        bgColor: '#ffffff',
        vlinkColor: '#551a8b',
        xmlEncoding: null,
        xmlVersion: null,
        xmlStandalone: false,
        onpointerlockchange: null,
        onpointerlockerror: null,
        onbeforecopy: null,
        onbeforecut: null,
        onbeforepaste: null,
        oncopy: null,
        oncut: null,
        onpaste: null,
        onsearch: null,
        onselectstart: null,
        onwheel: null,
        onwebkitfullscreenchange: null,
        onwebkitfullscreenerror: null,
        webkitIsFullScreen: false,
        webkitCurrentFullScreenElement: null,
        webkitFullscreenEnabled: true,
        webkitHidden: false,
        webkitVisibilityState: 'visible',
      } as unknown as Document, // Cast to Document, be mindful of missing properties if tests fail
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      // Add any other window properties Keycloak interacts with
      // For example, if it uses localStorage or sessionStorage directly:
      localStorage: {
        getItem: vi.fn(),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
        key: vi.fn(),
        length: 0,
      },
      sessionStorage: {
        getItem: vi.fn(),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
        key: vi.fn(),
        length: 0,
      },
      isSecureContext: true, // Assume secure context for tests
      setTimeout: vi.fn((fn: TimerHandler, ms?: number) => {
        if (typeof fn === 'function') {
          // In a test environment, you might want to execute immediately or control via test runner
          // For simplicity, just return a number
          return 1 as unknown as number; 
        }
        return 0 as unknown as number;
      }),
      clearTimeout: vi.fn(),
      fetch: vi.fn(), // Will be spied on and mocked below
      // Other properties
      innerHeight: 768,
      innerWidth: 1024,
      origin: 'http://localhost:3000',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any; // Use 'any' for stubbing, or create a more complete mock interface
    vi.stubGlobal('window', mockWindow);
    vi.stubGlobal('document', mockWindow.document); // Ensure document is also stubbed if accessed directly


    // Mock global.fetch for OIDC discovery
    global.fetch = vi.fn(async (url: RequestInfo | URL) => {
      const urlString = url.toString();
      if (urlString.includes('.well-known/openid-configuration')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            authorization_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/auth`,
            token_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/token`,
            logout_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/logout`,
            userinfo_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/userinfo`,
            check_session_iframe: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/login-status-iframe.html`,
          }),
        } as Response);
      } else if (urlString.includes('/realms/' + REALM + '/protocol/openid-connect/3p-cookies/step1.html')) {
        // Mock for the 3p cookies check iframe, assume cookies are supported
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

    keycloak = new Keycloak({ url: BASE_URL, realm: REALM, clientId: CLIENT_ID });
    
    // Standard init options for most tests, can be overridden
    const initOptions: IKeycloakInitOptions = {
      // onLoad: 'check-sso', // Example, adjust as needed
      // silentCheckSsoRedirectUri: 'http://localhost:3000/silent-check-sso.html',
      pkceMethod: 'S256', // Enable PKCE for most tests
    };
    
    try {
        await keycloak.init(initOptions);
    } catch (error) {
        console.error("Error during Keycloak init in test setup:", error);
        // Optionally fail the test here if init is critical for all tests in this block
        // throw error; 
    }
  });

  it('creates a login URL with default options', async () => {
    const loginUrlString = await keycloak.createLoginUrl({});
    const loginUrl = new URL(loginUrlString);

    expect(loginUrl.protocol).toBe('http:');
    expect(loginUrl.host).toBe('localhost:8080');
    expect(loginUrl.pathname).toBe(`/auth/realms/${REALM}/protocol/openid-connect/auth`);
    
    expect(loginUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(loginUrl.searchParams.get('redirect_uri')).toBe(DEFAULT_REDIRECT_URI);
    expect(loginUrl.searchParams.get('response_mode')).toBe('fragment'); // Default
    expect(loginUrl.searchParams.get('response_type')).toBe('code'); // Default
    expect(loginUrl.searchParams.get('scope')).toBe('openid'); // Default scope
    
    expect(loginUrl.searchParams.get('state')).toEqual(expect.any(String));
    expect(loginUrl.searchParams.get('nonce')).toEqual(expect.any(String));
    
    // Check for PKCE parameters (since pkceMethod is 'S256' by default in Keycloak class)
    expect(loginUrl.searchParams.get('code_challenge')).toEqual(expect.any(String));
    expect(loginUrl.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('creates a login URL with specific options', async () => {
    const specificRedirectUri = 'http://localhost:3000/specific-redirect';
    const loginOptions: IKeycloakLoginOptions = {
      redirectUri: specificRedirectUri,
      prompt: 'login',
      action: 'register',
      loginHint: 'testuser',
      locale: 'en',
      scope: 'openid email profile',
      acr: 'level1', // Test with acr, assuming it's handled as acr_values by default
      maxAge: 3600,
    };

    const loginUrlString = await keycloak.createLoginUrl(loginOptions);
    const loginUrl = new URL(loginUrlString);

    expect(loginUrl.pathname).toBe(`/auth/realms/${REALM}/protocol/openid-connect/auth`); // Action 'register' uses the same auth endpoint but could have specific params
    
    expect(loginUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(loginUrl.searchParams.get('redirect_uri')).toBe(specificRedirectUri);
    expect(loginUrl.searchParams.get('prompt')).toBe('login');
    expect(loginUrl.searchParams.get('kc_action')).toBe('register'); // kc_action for register
    expect(loginUrl.searchParams.get('login_hint')).toBe('testuser');
    expect(loginUrl.searchParams.get('ui_locales')).toBe('en');
    expect(loginUrl.searchParams.get('scope')).toBe('openid email profile');
    expect(loginUrl.searchParams.get('acr_values')).toBe('level1'); // Assuming acr option maps to acr_values
    expect(loginUrl.searchParams.get('max_age')).toBe('3600');

    expect(loginUrl.searchParams.get('state')).toEqual(expect.any(String));
    expect(loginUrl.searchParams.get('nonce')).toEqual(expect.any(String));
    expect(loginUrl.searchParams.get('code_challenge')).toEqual(expect.any(String));
    expect(loginUrl.searchParams.get('code_challenge_method')).toBe('S256');
  });

  it('correctly forms response_type and response_mode for different flows', async () => {
    // Test 'implicit' flow
    // Need to re-init for flow change or have a way to set flow per createLoginUrl call
    // For this test, let's re-init keycloak instance with a different flow.
    keycloak = new Keycloak({ url: BASE_URL, realm: REALM, clientId: CLIENT_ID });
    await keycloak.init({ flow: 'implicit' });
    
    let loginUrlString = await keycloak.createLoginUrl({});
    let loginUrl = new URL(loginUrlString);
    expect(loginUrl.searchParams.get('response_type')).toBe('id_token token');
    expect(loginUrl.searchParams.get('response_mode')).toBe('fragment'); // Default for implicit

    // Test 'hybrid' flow
    keycloak = new Keycloak({ url: BASE_URL, realm: REALM, clientId: CLIENT_ID });
    await keycloak.init({ flow: 'hybrid' });
    loginUrlString = await keycloak.createLoginUrl({});
    loginUrl = new URL(loginUrlString);
    expect(loginUrl.searchParams.get('response_type')).toBe('code id_token token');
    expect(loginUrl.searchParams.get('response_mode')).toBe('fragment'); // Default for hybrid
    
    // Test 'standard' flow with 'query' response_mode
    keycloak = new Keycloak({ url: BASE_URL, realm: REALM, clientId: CLIENT_ID });
    await keycloak.init({ flow: 'standard', responseMode: 'query' });
    loginUrlString = await keycloak.createLoginUrl({});
    loginUrl = new URL(loginUrlString);
    expect(loginUrl.searchParams.get('response_type')).toBe('code');
    expect(loginUrl.searchParams.get('response_mode')).toBe('query');
  });
  
  it('does not include PKCE parameters if pkceMethod is false', async () => {
    keycloak = new Keycloak({ url: BASE_URL, realm: REALM, clientId: CLIENT_ID });
    await keycloak.init({ pkceMethod: false });

    const loginUrlString = await keycloak.createLoginUrl({});
    const loginUrl = new URL(loginUrlString);

    expect(loginUrl.searchParams.get('code_challenge')).toBeNull();
    expect(loginUrl.searchParams.get('code_challenge_method')).toBeNull();
  });

  it('includes idpHint when provided', async () => {
    const loginOptions: IKeycloakLoginOptions = {
      idpHint: 'my-idp'
    };
    const loginUrlString = await keycloak.createLoginUrl(loginOptions);
    const loginUrl = new URL(loginUrlString);
    expect(loginUrl.searchParams.get('kc_idp_hint')).toBe('my-idp');
  });
});
