import { describe, it, expect, beforeEach, vi } from 'vitest';
import Keycloak, { type IKeycloakInitOptions, type IKeycloakLogoutOptions, type IKeycloakTokenParsed } from '../../lib/keycloak.ts';

// Constants
const BASE_URL = 'http://localhost:8080/auth';
const REALM = 'test-realm';
const CLIENT_ID = 'test-client';
const DEFAULT_REDIRECT_URI = 'http://localhost:3000/default-redirect';
const LOGOUT_ENDPOINT_PATH = `/realms/${REALM}/protocol/openid-connect/logout`;

interface MockWindow extends Window {
  // Add specific properties if needed
}

describe('createLogoutUrl', () => {
  let keycloak: Keycloak;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  let mockWindow: MockWindow;

  beforeEach(async () => {
    // Mock window and globals
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
        documentElement: {} as HTMLElement,
        activeElement: null,
        readyState: 'complete',
        head: { appendChild: vi.fn() } as unknown as HTMLHeadElement,
        defaultView: window,
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
        return Promise.resolve({
          ok: true,
          status: 200,
          json: async () => ({
            authorization_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/auth`,
            token_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/token`,
            logout_endpoint: `${BASE_URL}${LOGOUT_ENDPOINT_PATH}`, // Crucial for logout tests
            userinfo_endpoint: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/userinfo`,
            check_session_iframe: `${BASE_URL}/realms/${REALM}/protocol/openid-connect/login-status-iframe.html`,
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

    keycloak = new Keycloak({ url: BASE_URL, realm: REALM, clientId: CLIENT_ID });
    
    const initOptions: IKeycloakInitOptions = {}; // Default init options
    await keycloak.init(initOptions);
  });

  it('creates a logout URL with default options', () => {
    const logoutUrlString = keycloak.createLogoutUrl({});
    const logoutUrl = new URL(logoutUrlString);

    expect(logoutUrl.protocol).toBe('http:');
    expect(logoutUrl.host).toBe('localhost:8080'); // From BASE_URL
    expect(logoutUrl.pathname).toBe(`/auth${LOGOUT_ENDPOINT_PATH}`);
    
    expect(logoutUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    // Default redirectUri for logout is the current window.location.href
    expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(DEFAULT_REDIRECT_URI); 
    expect(logoutUrl.searchParams.get('id_token_hint')).toBeNull(); // No idToken by default
  });

  it('creates a logout URL with all options (redirectUri)', () => {
    const specificRedirectUri = 'http://localhost:3000/specific-logout-redirect';
    const options: IKeycloakLogoutOptions = {
      redirectUri: specificRedirectUri,
    };
    const logoutUrlString = keycloak.createLogoutUrl(options);
    const logoutUrl = new URL(logoutUrlString);

    expect(logoutUrl.pathname).toBe(`/auth${LOGOUT_ENDPOINT_PATH}`);
    expect(logoutUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(specificRedirectUri);
  });
  
  it('creates a logout URL with POST method option', () => {
    // When logoutMethod is POST, createLogoutUrl should just return the base endpoint URL
    // as parameters are expected to be in the body of the POST request.
    keycloak.logoutMethod = 'POST'; // Set logoutMethod on the instance
    const logoutUrlString = keycloak.createLogoutUrl({}); // Options like redirectUri are ignored for POST URL generation
    const logoutUrl = new URL(logoutUrlString);
    
    expect(logoutUrl.pathname).toBe(`/auth${LOGOUT_ENDPOINT_PATH}`);
    expect(logoutUrl.search).toBe(''); // No query parameters for POST logout URL
    
    // Reset for subsequent tests if needed, or ensure each test re-initializes keycloak
    keycloak.logoutMethod = 'GET'; 
  });

  it('creates a logout URL using the redirect URL passed during initialization', async () => {
    const initRedirectUri = 'http://localhost:3000/init-redirect';
    keycloak = new Keycloak({ url: BASE_URL, realm: REALM, clientId: CLIENT_ID });
    await keycloak.init({ redirectUri: initRedirectUri }); // Init with a specific redirectUri

    const logoutUrlString = keycloak.createLogoutUrl({}); // No options, should use init redirectUri
    const logoutUrl = new URL(logoutUrlString);

    expect(logoutUrl.pathname).toBe(`/auth${LOGOUT_ENDPOINT_PATH}`);
    expect(logoutUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(initRedirectUri);
  });

  it('creates a logout URL with the ID token hint when authenticated', () => {
    const mockIdToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    keycloak.idToken = mockIdToken;
    // Minimal tokenParsed, ensure it's not null/undefined if logic checks authenticated status via tokenParsed
    keycloak.tokenParsed = { sub: 'test-sub' } as IKeycloakTokenParsed; 
    keycloak.authenticated = true; // Explicitly set authenticated

    const logoutUrlString = keycloak.createLogoutUrl({});
    const logoutUrl = new URL(logoutUrlString);

    expect(logoutUrl.pathname).toBe(`/auth${LOGOUT_ENDPOINT_PATH}`);
    expect(logoutUrl.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(logoutUrl.searchParams.get('id_token_hint')).toBe(mockIdToken);
    expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(DEFAULT_REDIRECT_URI);

    // Clean up for other tests
    keycloak.idToken = undefined;
    keycloak.tokenParsed = undefined;
    keycloak.authenticated = false;
  });
});
