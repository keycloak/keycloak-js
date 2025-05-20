// --------------------------------------------- keycloak.js------------------------------------------------------------------------------------
const CONTENT_TYPE_JSON = 'application/json';

function Keycloak (config) {
    if (!(this instanceof Keycloak)) {
        throw new Error("The 'Keycloak' constructor must be invoked with 'new'.")
    }

    if (typeof config !== 'string' && !isObject(config)) {
        throw new Error("The 'Keycloak' constructor must be provided with a configuration object, or a URL to a JSON configuration file.");
    }

    if (isObject(config)) {
        const requiredProperties = 'oidcProvider' in config
            ? ['clientId']
            : ['url', 'realm', 'clientId'];

        for (const property of requiredProperties) {
            if (!config[property]) {
                throw new Error(`The configuration object is missing the required '${property}' property.`);
            }
        }
    }

    var kc = this;
    var adapter;
    var refreshQueue = [];
    var callbackStorage;

    var loginIframe = {
        enable: true,
        callbackList: [],
        interval: 5
    };

    kc.didInitialize = false;

    var useNonce = true;
    var logInfo = createLogger(console.info);
    var logWarn = createLogger(console.warn);

    if (!globalThis.isSecureContext) {
        logWarn(
            "[KEYCLOAK] Keycloak JS must be used in a 'secure context' to function properly as it relies on browser APIs that are otherwise not available.\n" +
            "Continuing to run your application insecurely will lead to unexpected behavior and breakage.\n\n" +
            "For more information see: https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts"
        );
    }

    kc.init = function (initOptions = {}) {
        if (kc.didInitialize) {
            throw new Error("A 'Keycloak' instance can only be initialized once.");
        }

        kc.didInitialize = true;

        kc.authenticated = false;

        callbackStorage = createCallbackStorage();
        var adapters = ['default', 'cordova', 'cordova-native'];

        if (adapters.indexOf(initOptions.adapter) > -1) {
            adapter = loadAdapter(initOptions.adapter);
        } else if (typeof initOptions.adapter === "object") {
            adapter = initOptions.adapter;
        } else {
            if (window.Cordova || window.cordova) {
                adapter = loadAdapter('cordova');
            } else {
                adapter = loadAdapter();
            }
        }

        if (typeof initOptions.useNonce !== 'undefined') {
            useNonce = initOptions.useNonce;
        }

        if (typeof initOptions.checkLoginIframe !== 'undefined') {
            loginIframe.enable = initOptions.checkLoginIframe;
        }

        if (initOptions.checkLoginIframeInterval) {
            loginIframe.interval = initOptions.checkLoginIframeInterval;
        }

        if (initOptions.onLoad === 'login-required') {
            kc.loginRequired = true;
        }

        if (initOptions.responseMode) {
            if (initOptions.responseMode === 'query' || initOptions.responseMode === 'fragment') {
                kc.responseMode = initOptions.responseMode;
            } else {
                throw 'Invalid value for responseMode';
            }
        }

        if (initOptions.flow) {
            switch (initOptions.flow) {
                case 'standard':
                    kc.responseType = 'code';
                    break;
                case 'implicit':
                    kc.responseType = 'id_token token';
                    break;
                case 'hybrid':
                    kc.responseType = 'code id_token token';
                    break;
                default:
                    throw 'Invalid value for flow';
            }
            kc.flow = initOptions.flow;
        }

        if (initOptions.timeSkew != null) {
            kc.timeSkew = initOptions.timeSkew;
        }

        if(initOptions.redirectUri) {
            kc.redirectUri = initOptions.redirectUri;
        }

        if (initOptions.silentCheckSsoRedirectUri) {
            kc.silentCheckSsoRedirectUri = initOptions.silentCheckSsoRedirectUri;
        }

        if (typeof initOptions.silentCheckSsoFallback === 'boolean') {
            kc.silentCheckSsoFallback = initOptions.silentCheckSsoFallback;
        } else {
            kc.silentCheckSsoFallback = true;
        }

        if (typeof initOptions.pkceMethod !== "undefined") {
            if (initOptions.pkceMethod !== "S256" && initOptions.pkceMethod !== false) {
                throw new TypeError(`Invalid value for pkceMethod', expected 'S256' or false but got ${initOptions.pkceMethod}.`);
            }

            kc.pkceMethod = initOptions.pkceMethod;
        } else {
            kc.pkceMethod = "S256";
        }

        if (typeof initOptions.enableLogging === 'boolean') {
            kc.enableLogging = initOptions.enableLogging;
        } else {
            kc.enableLogging = false;
        }

        if (initOptions.logoutMethod === 'POST') {
            kc.logoutMethod = 'POST';
        } else {
            kc.logoutMethod = 'GET';
        }

        if (typeof initOptions.scope === 'string') {
            kc.scope = initOptions.scope;
        }

        if (typeof initOptions.messageReceiveTimeout === 'number' && initOptions.messageReceiveTimeout > 0) {
            kc.messageReceiveTimeout = initOptions.messageReceiveTimeout;
        } else {
            kc.messageReceiveTimeout = 10000;
        }

        if (!kc.responseMode) {
            kc.responseMode = 'fragment';
        }
        if (!kc.responseType) {
            kc.responseType = 'code';
            kc.flow = 'standard';
        }

        var promise = createPromise();

        var initPromise = createPromise();
        initPromise.promise.then(function() {
            kc.onReady && kc.onReady(kc.authenticated);
            promise.setSuccess(kc.authenticated);
        }).catch(function(error) {
            promise.setError(error);
        });

        var configPromise = loadConfig();

        function onLoad() {
            var doLogin = function(prompt) {
                if (!prompt) {
                    options.prompt = 'none';
                }

                if (initOptions.locale) {
                    options.locale = initOptions.locale;
                }
                kc.login(options).then(function () {
                    initPromise.setSuccess();
                }).catch(function (error) {
                    initPromise.setError(error);
                });
            }

            var checkSsoSilently = async function() {
                var ifrm = document.createElement("iframe");
                var src = await kc.createLoginUrl({prompt: 'none', redirectUri: kc.silentCheckSsoRedirectUri});
                ifrm.setAttribute("src", src);
                ifrm.setAttribute("sandbox", "allow-storage-access-by-user-activation allow-scripts allow-same-origin");
                ifrm.setAttribute("title", "keycloak-silent-check-sso");
                ifrm.style.display = "none";
                document.body.appendChild(ifrm);

                var messageCallback = function(event) {
                    if (event.origin !== window.location.origin || ifrm.contentWindow !== event.source) {
                        return;
                    }

                    var oauth = parseCallback(event.data);
                    processCallback(oauth, initPromise);

                    document.body.removeChild(ifrm);
                    window.removeEventListener("message", messageCallback);
                };

                window.addEventListener("message", messageCallback);
            };

            var options = {};
            switch (initOptions.onLoad) {
                case 'check-sso':
                    if (loginIframe.enable) {
                        setupCheckLoginIframe().then(function() {
                            checkLoginIframe().then(function (unchanged) {
                                if (!unchanged) {
                                    kc.silentCheckSsoRedirectUri ? checkSsoSilently() : doLogin(false);
                                } else {
                                    initPromise.setSuccess();
                                }
                            }).catch(function (error) {
                                initPromise.setError(error);
                            });
                        });
                    } else {
                        kc.silentCheckSsoRedirectUri ? checkSsoSilently() : doLogin(false);
                    }
                    break;
                case 'login-required':
                    doLogin(true);
                    break;
                default:
                    throw 'Invalid value for onLoad';
            }
        }

        function processInit() {
            var callback = parseCallback(window.location.href);

            if (callback) {
                window.history.replaceState(window.history.state, null, callback.newUrl);
            }

            if (callback && callback.valid) {
                return setupCheckLoginIframe().then(function() {
                    processCallback(callback, initPromise);
                }).catch(function (error) {
                    initPromise.setError(error);
                });
            }

            if (initOptions.token && initOptions.refreshToken) {
                setToken(initOptions.token, initOptions.refreshToken, initOptions.idToken);

                if (loginIframe.enable) {
                    setupCheckLoginIframe().then(function() {
                        checkLoginIframe().then(function (unchanged) {
                            if (unchanged) {
                                kc.onAuthSuccess && kc.onAuthSuccess();
                                initPromise.setSuccess();
                                scheduleCheckIframe();
                            } else {
                                initPromise.setSuccess();
                            }
                        }).catch(function (error) {
                            initPromise.setError(error);
                        });
                    });
                } else {
                    kc.updateToken(-1).then(function() {
                        kc.onAuthSuccess && kc.onAuthSuccess();
                        initPromise.setSuccess();
                    }).catch(function(error) {
                        kc.onAuthError && kc.onAuthError();
                        if (initOptions.onLoad) {
                            onLoad();
                        } else {
                            initPromise.setError(error);
                        }
                    });
                }
            } else if (initOptions.onLoad) {
                onLoad();
            } else {
                initPromise.setSuccess();
            }
        }

        configPromise.then(function () {
            check3pCookiesSupported()
                .then(processInit)
                .catch(function (error) {
                    promise.setError(error);
                });
        });
        configPromise.catch(function (error) {
            promise.setError(error);
        });

        return promise.promise;
    }

    kc.login = function (options) {
        return adapter.login(options);
    }

    function generateRandomData(len) {
        if (typeof crypto === "undefined" || typeof crypto.getRandomValues === "undefined") {
            throw new Error("Web Crypto API is not available.");
        }

        return crypto.getRandomValues(new Uint8Array(len));
    }

    function generateCodeVerifier(len) {
        return generateRandomString(len, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
    }

    function generateRandomString(len, alphabet){
        var randomData = generateRandomData(len);
        var chars = new Array(len);
        for (var i = 0; i < len; i++) {
            chars[i] = alphabet.charCodeAt(randomData[i] % alphabet.length);
        }
        return String.fromCharCode.apply(null, chars);
    }

    async function generatePkceChallenge(pkceMethod, codeVerifier) {
        if (pkceMethod !== "S256") {
            throw new TypeError(`Invalid value for 'pkceMethod', expected 'S256' but got '${pkceMethod}'.`);
        }

        const hashBytes = new Uint8Array(await sha256Digest(codeVerifier));
        const encodedHash = bytesToBase64(hashBytes)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        return encodedHash;
    }

    function buildClaimsParameter(requestedAcr){
        var claims = {
            id_token: {
                acr: requestedAcr
            }
        }
        return JSON.stringify(claims);
    }

    kc.createLoginUrl = async function(options) {
        const state = createUUID();
        const nonce = createUUID();
        const redirectUri = adapter.redirectUri(options);
        const callbackState = {
            state,
            nonce,
            redirectUri: encodeURIComponent(redirectUri),
            loginOptions: options
        };

        if (options?.prompt) {
            callbackState.prompt = options.prompt;
        }

        const url = options?.action === 'register'
            ? kc.endpoints.register()
            : kc.endpoints.authorize();

        let scope = options?.scope || kc.scope;
        const scopeValues = scope ? scope.split(' ') : [];

        if (!scopeValues.includes('openid')) {
            scopeValues.unshift('openid');
        }

        scope = scopeValues.join(' ');

        const params = new URLSearchParams([
            ['client_id', kc.clientId],
            ['redirect_uri', redirectUri],
            ['state', state],
            ['response_mode', kc.responseMode],
            ['response_type', kc.responseType],
            ['scope', scope]
        ]);

        if (useNonce) {
            params.append('nonce', nonce);
        }

        if (options?.prompt) {
            params.append('prompt', options.prompt);
        }

        if (typeof options?.maxAge === 'number') {
            params.append('max_age', options.maxAge.toString());
        }

        if (options?.loginHint) {
            params.append('login_hint', options.loginHint);
        }

        if (options?.idpHint) {
            params.append('kc_idp_hint', options.idpHint);
        }

        if (options?.action && options.action !== 'register') {
            params.append('kc_action', options.action);
        }

        if (options?.locale) {
            params.append('ui_locales', options.locale);
        }

        if (options?.acr) {
            params.append('claims', buildClaimsParameter(options.acr));
        }

        if (options?.acrValues) {
            params.append('acr_values', options.acrValues);
        }

        if (kc.pkceMethod) {
            try {
                const codeVerifier = generateCodeVerifier(96);
                const pkceChallenge = await generatePkceChallenge(kc.pkceMethod, codeVerifier);

                callbackState.pkceCodeVerifier = codeVerifier;

                params.append('code_challenge', pkceChallenge);
                params.append('code_challenge_method', kc.pkceMethod);
            } catch (error) {
                throw new Error("Failed to generate PKCE challenge.", { cause: error });
            }
        }

        callbackStorage.add(callbackState);

        return `${url}?${params.toString()}`;
    }

    kc.logout = function(options) {
        return adapter.logout(options);
    }

    kc.createLogoutUrl = function(options) {
        const logoutMethod = options?.logoutMethod ?? kc.logoutMethod;
        const url = kc.endpoints.logout();

        if (logoutMethod === 'POST') {
            return url;
        }

        const params = new URLSearchParams([
            ['client_id', kc.clientId],
            ['post_logout_redirect_uri', adapter.redirectUri(options)]
        ]);

        if (kc.idToken) {
            params.append('id_token_hint', kc.idToken);
        }

        return `${url}?${params.toString()}`;
    }

    kc.register = function (options) {
        return adapter.register(options);
    }

    kc.createRegisterUrl = async function(options) {
        return await kc.createLoginUrl({ ...options, action: 'register' });
    }

    kc.createAccountUrl = function(options) {
        const url = getRealmUrl();

        if (!url) {
            throw new Error('Unable to create account URL, make sure the adapter not is configured using a generic OIDC provider.');
        }

        const params = new URLSearchParams([
            ['referrer', kc.clientId],
            ['referrer_uri', adapter.redirectUri(options)]
        ]);

        return `${url}/account?${params.toString()}`;
    }

    kc.accountManagement = function() {
        return adapter.accountManagement();
    }

    kc.hasRealmRole = function (role) {
        var access = kc.realmAccess;
        return !!access && access.roles.indexOf(role) >= 0;
    }

    kc.hasResourceRole = function(role, resource) {
        if (!kc.resourceAccess) {
            return false;
        }

        var access = kc.resourceAccess[resource || kc.clientId];
        return !!access && access.roles.indexOf(role) >= 0;
    }

    kc.loadUserProfile = async function() {
        const realmUrl = getRealmUrl();

        if (!realmUrl) {
            throw new Error('Unable to load user profile, make sure the adapter not is configured using a generic OIDC provider.');
        }

        const url = `${realmUrl}/account`;
        const profile = await fetchJSON(url, {
            headers: [buildAuthorizationHeader(kc.token)],
        })

        return (kc.profile = profile);
    }

    kc.loadUserInfo = async function() {
        const url = kc.endpoints.userinfo();
        const userInfo = await fetchJSON(url, {
            headers: [buildAuthorizationHeader(kc.token)],
        })

        return (kc.userInfo = userInfo);
    }

    kc.isTokenExpired = function(minValidity) {
        if (!kc.tokenParsed || (!kc.refreshToken && kc.flow !== 'implicit' )) {
            throw 'Not authenticated';
        }

        if (kc.timeSkew == null) {
            logInfo('[KEYCLOAK] Unable to determine if token is expired as timeskew is not set');
            return true;
        }

        var expiresIn = kc.tokenParsed['exp'] - Math.ceil(new Date().getTime() / 1000) + kc.timeSkew;
        if (minValidity) {
            if (isNaN(minValidity)) {
                throw 'Invalid minValidity';
            }
            expiresIn -= minValidity;
        }
        return expiresIn < 0;
    }

    kc.updateToken = function(minValidity) {
        var promise = createPromise();

        if (!kc.refreshToken) {
            promise.setError();
            return promise.promise;
        }

        minValidity = minValidity || 5;

        var exec = function() {
            var refreshToken = false;
            if (minValidity === -1) {
                refreshToken = true;
                logInfo('[KEYCLOAK] Refreshing token: forced refresh');
            } else if (!kc.tokenParsed || kc.isTokenExpired(minValidity)) {
                refreshToken = true;
                logInfo('[KEYCLOAK] Refreshing token: token expired');
            }

            if (!refreshToken) {
                promise.setSuccess(false);
            } else {
                refreshQueue.push(promise);

                if (refreshQueue.length === 1) {
                    const url = kc.endpoints.token();
                    let timeLocal = new Date().getTime();

                    fetchRefreshToken(url, kc.refreshToken, kc.clientId)
                    .then((response) => {
                        logInfo('[KEYCLOAK] Token refreshed');

                        timeLocal = (timeLocal + new Date().getTime()) / 2;

                        setToken(response['access_token'], response['refresh_token'], response['id_token'], timeLocal);

                        kc.onAuthRefreshSuccess && kc.onAuthRefreshSuccess();
                        for (let p = refreshQueue.pop(); p != null; p = refreshQueue.pop()) {
                            p.setSuccess(true);
                        }
                    })
                    .catch((error) => {
                        logWarn('[KEYCLOAK] Failed to refresh token');

                        if (error instanceof NetworkError && error.response.status === 400) {
                            kc.clearToken();
                        }

                        kc.onAuthRefreshError && kc.onAuthRefreshError();
                        for (let p = refreshQueue.pop(); p != null; p = refreshQueue.pop()) {
                            p.setError(error);
                        }
                    });
                }
            }
        }

        if (loginIframe.enable) {
            var iframePromise = checkLoginIframe();
            iframePromise.then(function() {
                exec();
            }).catch(function(error) {
                promise.setError(error);
            });
        } else {
            exec();
        }

        return promise.promise;
    }

    kc.clearToken = function() {
        if (kc.token) {
            setToken(null, null, null);
            kc.onAuthLogout && kc.onAuthLogout();
            if (kc.loginRequired) {
                kc.login();
            }
        }
    }

    function getRealmUrl() {
        if (typeof kc.authServerUrl !== 'undefined') {
            if (kc.authServerUrl.charAt(kc.authServerUrl.length - 1) === '/') {
                return kc.authServerUrl + 'realms/' + encodeURIComponent(kc.realm);
            } else {
                return kc.authServerUrl + '/realms/' + encodeURIComponent(kc.realm);
            }
        } else {
            return undefined;
        }
    }

    function getOrigin() {
        if (!window.location.origin) {
            return window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port: '');
        } else {
            return window.location.origin;
        }
    }

    function processCallback(oauth, promise) {
        var code = oauth.code;
        var error = oauth.error;
        var prompt = oauth.prompt;

        var timeLocal = new Date().getTime();

        if (oauth['kc_action_status']) {
            kc.onActionUpdate && kc.onActionUpdate(oauth['kc_action_status'], oauth['kc_action']);
        }

        if (error) {
            if (prompt !== 'none') {
                if (oauth.error_description && oauth.error_description === "authentication_expired") {
                    kc.login(oauth.loginOptions);
                } else {
                    var errorData = { error: error, error_description: oauth.error_description };
                    kc.onAuthError && kc.onAuthError(errorData);
                    promise && promise.setError(errorData);
                }
            } else {
                promise && promise.setSuccess();
            }
            return;
        } else if ((kc.flow !== 'standard') && (oauth.access_token || oauth.id_token)) {
            authSuccess(oauth.access_token, null, oauth.id_token, true);
        }

        if ((kc.flow !== 'implicit') && code) {
            fetchAccessToken(kc.endpoints.token(), code, kc.clientId, decodeURIComponent(oauth.redirectUri), oauth.pkceCodeVerifier)
            .then((response) => {
                authSuccess(response['access_token'], response['refresh_token'], response['id_token'], kc.flow === 'standard');
                scheduleCheckIframe();
            })
            .catch((error) => {
                kc.onAuthError && kc.onAuthError();
                promise && promise.setError(error);
            });
        }

        function authSuccess(accessToken, refreshToken, idToken, fulfillPromise) {
            timeLocal = (timeLocal + new Date().getTime()) / 2;

            setToken(accessToken, refreshToken, idToken, timeLocal);

            if (useNonce && (kc.idTokenParsed && kc.idTokenParsed.nonce !== oauth.storedNonce)) {
                logInfo('[KEYCLOAK] Invalid nonce, clearing token');
                kc.clearToken();
                promise && promise.setError();
            } else {
                if (fulfillPromise) {
                    kc.onAuthSuccess && kc.onAuthSuccess();
                    promise && promise.setSuccess();
                }
            }
        }

    }

    function loadConfig() {
        var promise = createPromise();
        var configUrl;

        if (typeof config === 'string') {
            configUrl = config;
        }

        function setupOidcEndoints(oidcConfiguration) {
            if (!oidcConfiguration) {
                kc.endpoints = {
                    authorize: function() {
                        return getRealmUrl() + '/protocol/openid-connect/auth';
                    },
                    token: function() {
                        return getRealmUrl() + '/protocol/openid-connect/token';
                    },
                    logout: function() {
                        return getRealmUrl() + '/protocol/openid-connect/logout';
                    },
                    checkSessionIframe: function() {
                        return getRealmUrl() + '/protocol/openid-connect/login-status-iframe.html';
                    },
                    thirdPartyCookiesIframe: function() {
                        return getRealmUrl() + '/protocol/openid-connect/3p-cookies/step1.html';
                    },
                    register: function() {
                        return getRealmUrl() + '/protocol/openid-connect/registrations';
                    },
                    userinfo: function() {
                        return getRealmUrl() + '/protocol/openid-connect/userinfo';
                    }
                };
            } else {
                kc.endpoints = {
                    authorize: function() {
                        return oidcConfiguration.authorization_endpoint;
                    },
                    token: function() {
                        return oidcConfiguration.token_endpoint;
                    },
                    logout: function() {
                        if (!oidcConfiguration.end_session_endpoint) {
                            throw "Not supported by the OIDC server";
                        }
                        return oidcConfiguration.end_session_endpoint;
                    },
                    checkSessionIframe: function() {
                        if (!oidcConfiguration.check_session_iframe) {
                            throw "Not supported by the OIDC server";
                        }
                        return oidcConfiguration.check_session_iframe;
                    },
                    register: function() {
                        throw 'Redirection to "Register user" page not supported in standard OIDC mode';
                    },
                    userinfo: function() {
                        if (!oidcConfiguration.userinfo_endpoint) {
                            throw "Not supported by the OIDC server";
                        }
                        return oidcConfiguration.userinfo_endpoint;
                    }
                }
            }
        }

        if (configUrl) {
            fetchJsonConfig(configUrl)
            .then((config) => {
                kc.authServerUrl = config['auth-server-url'];
                kc.realm = config.realm;
                kc.clientId = config.resource;
                setupOidcEndoints(null);
                promise.setSuccess();
            })
            .catch((error) => {
                promise.setError(error);
            });
        } else {
            kc.clientId = config.clientId;

            var oidcProvider = config['oidcProvider'];
            if (!oidcProvider) {
                kc.authServerUrl = config.url;
                kc.realm = config.realm;
                setupOidcEndoints(null);
                promise.setSuccess();
            } else {
                if (typeof oidcProvider === 'string') {
                    var oidcProviderConfigUrl;
                    if (oidcProvider.charAt(oidcProvider.length - 1) === '/') {
                        oidcProviderConfigUrl = oidcProvider + '.well-known/openid-configuration';
                    } else {
                        oidcProviderConfigUrl = oidcProvider + '/.well-known/openid-configuration';
                    }

                    fetchOpenIdConfig(oidcProviderConfigUrl)
                    .then((config) => {
                        setupOidcEndoints(config);
                        promise.setSuccess();
                    })
                    .catch((error) => {
                        promise.setError(error);
                    });
                } else {
                    setupOidcEndoints(oidcProvider);
                    promise.setSuccess();
                }
            }
        }

        return promise.promise;
    }

    function setToken(token, refreshToken, idToken, timeLocal) {
        if (kc.tokenTimeoutHandle) {
            clearTimeout(kc.tokenTimeoutHandle);
            kc.tokenTimeoutHandle = null;
        }

        if (refreshToken) {
            kc.refreshToken = refreshToken;
            kc.refreshTokenParsed = decodeToken(refreshToken);
        } else {
            delete kc.refreshToken;
            delete kc.refreshTokenParsed;
        }

        if (idToken) {
            kc.idToken = idToken;
            kc.idTokenParsed = decodeToken(idToken);
        } else {
            delete kc.idToken;
            delete kc.idTokenParsed;
        }

        if (token) {
            kc.token = token;
            kc.tokenParsed = decodeToken(token);
            kc.sessionId = kc.tokenParsed.sid;
            kc.authenticated = true;
            kc.subject = kc.tokenParsed.sub;
            kc.realmAccess = kc.tokenParsed.realm_access;
            kc.resourceAccess = kc.tokenParsed.resource_access;

            if (timeLocal) {
                kc.timeSkew = Math.floor(timeLocal / 1000) - kc.tokenParsed.iat;
            }

            if (kc.timeSkew != null) {
                logInfo('[KEYCLOAK] Estimated time difference between browser and server is ' + kc.timeSkew + ' seconds');

                if (kc.onTokenExpired) {
                    var expiresIn = (kc.tokenParsed['exp'] - (new Date().getTime() / 1000) + kc.timeSkew) * 1000;
                    logInfo('[KEYCLOAK] Token expires in ' + Math.round(expiresIn / 1000) + ' s');
                    if (expiresIn <= 0) {
                        kc.onTokenExpired();
                    } else {
                        kc.tokenTimeoutHandle = setTimeout(kc.onTokenExpired, expiresIn);
                    }
                }
            }
        } else {
            delete kc.token;
            delete kc.tokenParsed;
            delete kc.subject;
            delete kc.realmAccess;
            delete kc.resourceAccess;

            kc.authenticated = false;
        }
    }

    function createUUID() {
        if (typeof crypto === "undefined" || typeof crypto.randomUUID === "undefined") {
            throw new Error("Web Crypto API is not available.");
        }

        return crypto.randomUUID();
    }

    function parseCallback(url) {
        var oauth = parseCallbackUrl(url);
        if (!oauth) {
            return;
        }

        var oauthState = callbackStorage.get(oauth.state);

        if (oauthState) {
            oauth.valid = true;
            oauth.redirectUri = oauthState.redirectUri;
            oauth.storedNonce = oauthState.nonce;
            oauth.prompt = oauthState.prompt;
            oauth.pkceCodeVerifier = oauthState.pkceCodeVerifier;
            oauth.loginOptions = oauthState.loginOptions;
        }

        return oauth;
    }

    function parseCallbackUrl(url) {
        var supportedParams;
        switch (kc.flow) {
            case 'standard':
                supportedParams = ['code', 'state', 'session_state', 'kc_action_status', 'kc_action', 'iss'];
                break;
            case 'implicit':
                supportedParams = ['access_token', 'token_type', 'id_token', 'state', 'session_state', 'expires_in', 'kc_action_status', 'kc_action', 'iss'];
                break;
            case 'hybrid':
                supportedParams = ['access_token', 'token_type', 'id_token', 'code', 'state', 'session_state', 'expires_in', 'kc_action_status', 'kc_action', 'iss'];
                break;
        }

        supportedParams.push('error');
        supportedParams.push('error_description');
        supportedParams.push('error_uri');

        var queryIndex = url.indexOf('?');
        var fragmentIndex = url.indexOf('#');

        var newUrl;
        var parsed;

        if (kc.responseMode === 'query' && queryIndex !== -1) {
            newUrl = url.substring(0, queryIndex);
            parsed = parseCallbackParams(url.substring(queryIndex + 1, fragmentIndex !== -1 ? fragmentIndex : url.length), supportedParams);
            if (parsed.paramsString !== '') {
                newUrl += '?' + parsed.paramsString;
            }
            if (fragmentIndex !== -1) {
                newUrl += url.substring(fragmentIndex);
            }
        } else if (kc.responseMode === 'fragment' && fragmentIndex !== -1) {
            newUrl = url.substring(0, fragmentIndex);
            parsed = parseCallbackParams(url.substring(fragmentIndex + 1), supportedParams);
            if (parsed.paramsString !== '') {
                newUrl += '#' + parsed.paramsString;
            }
        }

        if (parsed && parsed.oauthParams) {
            if (kc.flow === 'standard' || kc.flow === 'hybrid') {
                if ((parsed.oauthParams.code || parsed.oauthParams.error) && parsed.oauthParams.state) {
                    parsed.oauthParams.newUrl = newUrl;
                    return parsed.oauthParams;
                }
            } else if (kc.flow === 'implicit') {
                if ((parsed.oauthParams.access_token || parsed.oauthParams.error) && parsed.oauthParams.state) {
                    parsed.oauthParams.newUrl = newUrl;
                    return parsed.oauthParams;
                }
            }
        }
    }

    function parseCallbackParams(paramsString, supportedParams) {
        var p = paramsString.split('&');
        var result = {
            paramsString: '',
            oauthParams: {}
        }
        for (var i = 0; i < p.length; i++) {
            var split = p[i].indexOf("=");
            var key = p[i].slice(0, split);
            if (supportedParams.indexOf(key) !== -1) {
                result.oauthParams[key] = p[i].slice(split + 1);
            } else {
                if (result.paramsString !== '') {
                    result.paramsString += '&';
                }
                result.paramsString += p[i];
            }
        }
        return result;
    }

    function createPromise() {
        var p = {
            setSuccess: function(result) {
                p.resolve(result);
            },

            setError: function(result) {
                p.reject(result);
            }
        };
        p.promise = new Promise(function(resolve, reject) {
            p.resolve = resolve;
            p.reject = reject;
        });

        return p;
    }

    function applyTimeoutToPromise(promise, timeout, errorMessage) {
        var timeoutHandle = null;
        var timeoutPromise = new Promise(function (resolve, reject) {
            timeoutHandle = setTimeout(function () {
                reject({ "error": errorMessage || "Promise is not settled within timeout of " + timeout + "ms" });
            }, timeout);
        });

        return Promise.race([promise, timeoutPromise]).finally(function () {
            clearTimeout(timeoutHandle);
        });
    }

    function setupCheckLoginIframe() {
        var promise = createPromise();

        if (!loginIframe.enable) {
            promise.setSuccess();
            return promise.promise;
        }

        if (loginIframe.iframe) {
            promise.setSuccess();
            return promise.promise;
        }

        var iframe = document.createElement('iframe');
        loginIframe.iframe = iframe;

        iframe.onload = function() {
            var authUrl = kc.endpoints.authorize();
            if (authUrl.charAt(0) === '/') {
                loginIframe.iframeOrigin = getOrigin();
            } else {
                loginIframe.iframeOrigin = authUrl.substring(0, authUrl.indexOf('/', 8));
            }
            promise.setSuccess();
        }

        var src = kc.endpoints.checkSessionIframe();
        iframe.setAttribute('src', src );
        iframe.setAttribute('sandbox', 'allow-storage-access-by-user-activation allow-scripts allow-same-origin');
        iframe.setAttribute('title', 'keycloak-session-iframe' );
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        var messageCallback = function(event) {
            if ((event.origin !== loginIframe.iframeOrigin) || (loginIframe.iframe.contentWindow !== event.source)) {
                return;
            }

            if (!(event.data === 'unchanged' || event.data === 'changed' || event.data === 'error')) {
                return;
            }


            if (event.data !== 'unchanged') {
                kc.clearToken();
            }

            var callbacks = loginIframe.callbackList.splice(0, loginIframe.callbackList.length);

            for (var i = callbacks.length - 1; i >= 0; --i) {
                var promise = callbacks[i];
                if (event.data === 'error') {
                    promise.setError();
                } else {
                    promise.setSuccess(event.data === 'unchanged');
                }
            }
        };

        window.addEventListener('message', messageCallback, false);

        return promise.promise;
    }

    function scheduleCheckIframe() {
        if (loginIframe.enable) {
            if (kc.token) {
                setTimeout(function() {
                    checkLoginIframe().then(function(unchanged) {
                        if (unchanged) {
                            scheduleCheckIframe();
                        }
                    });
                }, loginIframe.interval * 1000);
            }
        }
    }

    function checkLoginIframe() {
        var promise = createPromise();

        if (loginIframe.iframe && loginIframe.iframeOrigin ) {
            var msg = kc.clientId + ' ' + (kc.sessionId ? kc.sessionId : '');
            loginIframe.callbackList.push(promise);
            var origin = loginIframe.iframeOrigin;
            if (loginIframe.callbackList.length === 1) {
                loginIframe.iframe.contentWindow.postMessage(msg, origin);
            }
        } else {
            promise.setSuccess();
        }

        return promise.promise;
    }

    function check3pCookiesSupported() {
        var promise = createPromise();

        if ((loginIframe.enable || kc.silentCheckSsoRedirectUri) && typeof kc.endpoints.thirdPartyCookiesIframe === 'function') {
            var iframe = document.createElement('iframe');
            iframe.setAttribute('src', kc.endpoints.thirdPartyCookiesIframe());
            iframe.setAttribute('sandbox', 'allow-storage-access-by-user-activation allow-scripts allow-same-origin');
            iframe.setAttribute('title', 'keycloak-3p-check-iframe' );
            iframe.style.display = 'none';
            document.body.appendChild(iframe);

            var messageCallback = function(event) {
                if (iframe.contentWindow !== event.source) {
                    return;
                }

                if (event.data !== "supported" && event.data !== "unsupported") {
                    return;
                } else if (event.data === "unsupported") {
                    logWarn(
                        "[KEYCLOAK] Your browser is blocking access to 3rd-party cookies, this means:\n\n" +
                        " - It is not possible to retrieve tokens without redirecting to the Keycloak server (a.k.a. no support for silent authentication).\n" +
                        " - It is not possible to automatically detect changes to the session status (such as the user logging out in another tab).\n\n" +
                        "For more information see: https://www.keycloak.org/securing-apps/javascript-adapter#_modern_browsers"
                    );

                    loginIframe.enable = false;
                    if (kc.silentCheckSsoFallback) {
                        kc.silentCheckSsoRedirectUri = false;
                    }
                }

                document.body.removeChild(iframe);
                window.removeEventListener("message", messageCallback);
                promise.setSuccess();
            };

            window.addEventListener('message', messageCallback, false);
        } else {
            promise.setSuccess();
        }

        return applyTimeoutToPromise(promise.promise, kc.messageReceiveTimeout, "Timeout when waiting for 3rd party check iframe message.");
    }

    function loadAdapter(type) {
        if (!type || type === 'default') {
            return {
                login: async function(options) {
                    window.location.assign(await kc.createLoginUrl(options));
                    return createPromise().promise;
                },

                logout: async function(options) {

                    const logoutMethod = options?.logoutMethod ?? kc.logoutMethod;
                    if (logoutMethod === "GET") {
                        window.location.replace(kc.createLogoutUrl(options));
                        return;
                    }

                    const form = document.createElement("form");

                    form.setAttribute("method", "POST");
                    form.setAttribute("action", kc.createLogoutUrl(options));
                    form.style.display = "none";

                    const data = {
                        id_token_hint: kc.idToken,
                        client_id: kc.clientId,
                        post_logout_redirect_uri: adapter.redirectUri(options)
                    };

                    for (const [name, value] of Object.entries(data)) {
                        const input = document.createElement("input");

                        input.setAttribute("type", "hidden");
                        input.setAttribute("name", name);
                        input.setAttribute("value", value);

                        form.appendChild(input);
                    }

                    document.body.appendChild(form);
                    form.submit();
                },

                register: async function(options) {
                    window.location.assign(await kc.createRegisterUrl(options));
                    return createPromise().promise;
                },

                accountManagement : function() {
                    var accountUrl = kc.createAccountUrl();
                    if (typeof accountUrl !== 'undefined') {
                        window.location.href = accountUrl;
                    } else {
                        throw "Not supported by the OIDC server";
                    }
                    return createPromise().promise;
                },

                redirectUri: function(options) {
                    return options?.redirectUri || kc.redirectUri || location.href;
                }
            };
        }

        if (type === 'cordova') {
            loginIframe.enable = false;
            var cordovaOpenWindowWrapper = function(loginUrl, target, options) {
                if (window.cordova && window.cordova.InAppBrowser) {
                    return window.cordova.InAppBrowser.open(loginUrl, target, options);
                } else {
                    return window.open(loginUrl, target, options);
                }
            };

            var shallowCloneCordovaOptions = function (userOptions) {
                if (userOptions && userOptions.cordovaOptions) {
                    return Object.keys(userOptions.cordovaOptions).reduce(function (options, optionName) {
                        options[optionName] = userOptions.cordovaOptions[optionName];
                        return options;
                    }, {});
                } else {
                    return {};
                }
            };

            var formatCordovaOptions = function (cordovaOptions) {
                return Object.keys(cordovaOptions).reduce(function (options, optionName) {
                    options.push(optionName+"="+cordovaOptions[optionName]);
                    return options;
                }, []).join(",");
            };

            var createCordovaOptions = function (userOptions) {
                var cordovaOptions = shallowCloneCordovaOptions(userOptions);
                cordovaOptions.location = 'no';
                if (userOptions && userOptions.prompt === 'none') {
                    cordovaOptions.hidden = 'yes';
                }
                return formatCordovaOptions(cordovaOptions);
            };

            var getCordovaRedirectUri = function() {
                return kc.redirectUri || 'http://localhost';
            }

            return {
                login: async function(options) {
                    var promise = createPromise();

                    var cordovaOptions = createCordovaOptions(options);
                    var loginUrl = await kc.createLoginUrl(options);
                    var ref = cordovaOpenWindowWrapper(loginUrl, '_blank', cordovaOptions);
                    var completed = false;

                    var closed = false;
                    var closeBrowser = function() {
                        closed = true;
                        ref.close();
                    };

                    ref.addEventListener('loadstart', function(event) {
                        if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
                            var callback = parseCallback(event.url);
                            processCallback(callback, promise);
                            closeBrowser();
                            completed = true;
                        }
                    });

                    ref.addEventListener('loaderror', function(event) {
                        if (!completed) {
                            if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
                                var callback = parseCallback(event.url);
                                processCallback(callback, promise);
                                closeBrowser();
                                completed = true;
                            } else {
                                promise.setError();
                                closeBrowser();
                            }
                        }
                    });

                    ref.addEventListener('exit', function(event) {
                        if (!closed) {
                            promise.setError({
                                reason: "closed_by_user"
                            });
                        }
                    });

                    return promise.promise;
                },

                logout: function(options) {
                    var promise = createPromise();

                    var logoutUrl = kc.createLogoutUrl(options);
                    var ref = cordovaOpenWindowWrapper(logoutUrl, '_blank', 'location=no,hidden=yes,clearcache=yes');

                    var error;

                    ref.addEventListener('loadstart', function(event) {
                        if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
                            ref.close();
                        }
                    });

                    ref.addEventListener('loaderror', function(event) {
                        if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
                            ref.close();
                        } else {
                            error = true;
                            ref.close();
                        }
                    });

                    ref.addEventListener('exit', function(event) {
                        if (error) {
                            promise.setError();
                        } else {
                            kc.clearToken();
                            promise.setSuccess();
                        }
                    });

                    return promise.promise;
                },

                register : async function(options) {
                    var promise = createPromise();
                    var registerUrl = await kc.createRegisterUrl();
                    var cordovaOptions = createCordovaOptions(options);
                    var ref = cordovaOpenWindowWrapper(registerUrl, '_blank', cordovaOptions);
                    ref.addEventListener('loadstart', function(event) {
                        if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
                            ref.close();
                            var oauth = parseCallback(event.url);
                            processCallback(oauth, promise);
                        }
                    });
                    return promise.promise;
                },

                accountManagement : function() {
                    var accountUrl = kc.createAccountUrl();
                    if (typeof accountUrl !== 'undefined') {
                        var ref = cordovaOpenWindowWrapper(accountUrl, '_blank', 'location=no');
                        ref.addEventListener('loadstart', function(event) {
                            if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
                                ref.close();
                            }
                        });
                    } else {
                        throw "Not supported by the OIDC server";
                    }
                },

                redirectUri: function(options) {
                    return getCordovaRedirectUri();
                }
            }
        }

        if (type === 'cordova-native') {
            loginIframe.enable = false;

            return {
                login: async function(options) {
                    var promise = createPromise();
                    var loginUrl = await kc.createLoginUrl(options);

                    universalLinks.subscribe('keycloak', function(event) {
                        universalLinks.unsubscribe('keycloak');
                        window.cordova.plugins.browsertab.close();
                        var oauth = parseCallback(event.url);
                        processCallback(oauth, promise);
                    });

                    window.cordova.plugins.browsertab.openUrl(loginUrl);
                    return promise.promise;
                },

                logout: function(options) {
                    var promise = createPromise();
                    var logoutUrl = kc.createLogoutUrl(options);

                    universalLinks.subscribe('keycloak', function(event) {
                        universalLinks.unsubscribe('keycloak');
                        window.cordova.plugins.browsertab.close();
                        kc.clearToken();
                        promise.setSuccess();
                    });

                    window.cordova.plugins.browsertab.openUrl(logoutUrl);
                    return promise.promise;
                },

                register : async function(options) {
                    var promise = createPromise();
                    var registerUrl = await kc.createRegisterUrl(options);
                    universalLinks.subscribe('keycloak' , function(event) {
                        universalLinks.unsubscribe('keycloak');
                        window.cordova.plugins.browsertab.close();
                        var oauth = parseCallback(event.url);
                        processCallback(oauth, promise);
                    });
                    window.cordova.plugins.browsertab.openUrl(registerUrl);
                    return promise.promise;

                },

                accountManagement : function() {
                    var accountUrl = kc.createAccountUrl();
                    if (typeof accountUrl !== 'undefined') {
                        window.cordova.plugins.browsertab.openUrl(accountUrl);
                    } else {
                        throw "Not supported by the OIDC server";
                    }
                },

                redirectUri: function(options) {
                    if (options && options.redirectUri) {
                        return options.redirectUri;
                    } else if (kc.redirectUri) {
                        return kc.redirectUri;
                    } else {
                        return "http://localhost";
                    }
                }
            }
        }

        throw 'invalid adapter type: ' + type;
    }

    const STORAGE_KEY_PREFIX = 'kc-callback-';

    var LocalStorage = function() {
        if (!(this instanceof LocalStorage)) {
            return new LocalStorage();
        }

        localStorage.setItem('kc-test', 'test');
        localStorage.removeItem('kc-test');

        var cs = this;

        function clearInvalidValues() {
            const currentTime = Date.now();

            for (const [key, value] of getStoredEntries()) {
                const expiry = parseExpiry(value);

                if (expiry === null || expiry < currentTime) {
                    localStorage.removeItem(key);
                }
            }
        }

        function clearAllValues() {
            for (const [key] of getStoredEntries()) {
                localStorage.removeItem(key);
            }
        }

        function getStoredEntries() {
            return Object.entries(localStorage).filter(([key]) => key.startsWith(STORAGE_KEY_PREFIX));
        }

        function parseExpiry(value) {
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

        cs.get = function(state) {
            if (!state) {
                return;
            }

            var key = STORAGE_KEY_PREFIX + state;
            var value = localStorage.getItem(key);
            if (value) {
                localStorage.removeItem(key);
                value = JSON.parse(value);
            }

            clearInvalidValues();
            return value;
        };

        cs.add = function(state) {
            clearInvalidValues();

            const key = STORAGE_KEY_PREFIX + state.state;
            const value = JSON.stringify({
                ...state,
                expires: Date.now() + (60 * 60 * 1000)
            });

            try {
                localStorage.setItem(key, value);
            } catch (error) {
                clearAllValues();
                localStorage.setItem(key, value);
            }
        };
    };

    var CookieStorage = function() {
        if (!(this instanceof CookieStorage)) {
            return new CookieStorage();
        }

        var cs = this;

        cs.get = function(state) {
            if (!state) {
                return;
            }

            var value = getCookie(STORAGE_KEY_PREFIX + state);
            setCookie(STORAGE_KEY_PREFIX + state, '', cookieExpiration(-100));
            if (value) {
                return JSON.parse(value);
            }
        };

        cs.add = function(state) {
            setCookie(STORAGE_KEY_PREFIX + state.state, JSON.stringify(state), cookieExpiration(60));
        };

        cs.removeItem = function(key) {
            setCookie(key, '', cookieExpiration(-100));
        };

        var cookieExpiration = function (minutes) {
            var exp = new Date();
            exp.setTime(exp.getTime() + (minutes*60*1000));
            return exp;
        };

        var getCookie = function (key) {
            var name = key + '=';
            var ca = document.cookie.split(';');
            for (var i = 0; i < ca.length; i++) {
                var c = ca[i];
                while (c.charAt(0) === ' ') {
                    c = c.substring(1);
                }
                if (c.indexOf(name) === 0) {
                    return c.substring(name.length, c.length);
                }
            }
            return '';
        };

        var setCookie = function (key, value, expirationDate) {
            var cookie = key + '=' + value + '; '
                + 'expires=' + expirationDate.toUTCString() + '; ';
            document.cookie = cookie;
        }
    };

    function createCallbackStorage() {
        try {
            return new LocalStorage();
        } catch (err) {
        }

        return new CookieStorage();
    }

    function createLogger(fn) {
        return function() {
            if (kc.enableLogging) {
                fn.apply(console, Array.prototype.slice.call(arguments));
            }
        };
    }
}

export default Keycloak;

function bytesToBase64(bytes) {
    const binString = String.fromCodePoint(...bytes);
    return btoa(binString);
}

async function sha256Digest(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);

    if (typeof crypto === "undefined" || typeof crypto.subtle === "undefined") {
        throw new Error("Web Crypto API is not available.");
    }

    return await crypto.subtle.digest("SHA-256", data);
}

function decodeToken(token) {
    const [header, payload] = token.split(".");

    if (typeof payload !== "string") {
        throw new Error("Unable to decode token, payload not found.");
    }

    let decoded;

    try {
        decoded = base64UrlDecode(payload);
    } catch (error) {
        throw new Error("Unable to decode token, payload is not a valid Base64URL value.", { cause: error });
    }

    try {
        return JSON.parse(decoded);
    } catch (error) {
        throw new Error("Unable to decode token, payload is not a valid JSON value.", { cause: error });
    }
}

function base64UrlDecode(input) {
    let output = input
        .replaceAll("-", "+")
        .replaceAll("_", "/");

    switch (output.length % 4) {
        case 0:
            break;
        case 2:
            output += "==";
            break;
        case 3:
            output += "=";
            break;
        default:
            throw new Error("Input is not of the correct length.");
    }

    try {
        return b64DecodeUnicode(output);
    } catch (error) {
        return atob(output);
    }
}

function b64DecodeUnicode(input) {
    return decodeURIComponent(atob(input).replace(/(.)/g, (m, p) => {
        let code = p.charCodeAt(0).toString(16).toUpperCase();

        if (code.length < 2) {
            code = "0" + code;
        }

        return "%" + code;
    }));
}

function isObject(input) {
    return typeof input === 'object' && input !== null;
}

async function fetchJsonConfig(url) {
    return await fetchJSON(url);
}

async function fetchOpenIdConfig(url) {
    return await fetchJSON(url);
}

async function fetchAccessToken(url, code, clientId, redirectUri, pkceCodeVerifier) {
    const body = new URLSearchParams([
        ['code', code],
        ['grant_type', 'authorization_code'],
        ['client_id', clientId],
        ['redirect_uri', redirectUri]
    ]);

    if (pkceCodeVerifier) {
        body.append('code_verifier', pkceCodeVerifier);
    }

    return await fetchJSON(url, {
        method: 'POST',
        credentials: 'include',
        body,
    })
}

async function fetchRefreshToken(url, refreshToken, clientId) {
    const body = new URLSearchParams([
        ['grant_type', 'refresh_token'],
        ['refresh_token', refreshToken],
        ['client_id', clientId]
    ]);

    return await fetchJSON(url, {
        method: 'POST',
        credentials: 'include',
        body,
    })
}

async function fetchJSON(url, init = {}) {
    const headers = new Headers(init.headers);
    headers.set("Accept", CONTENT_TYPE_JSON);

    const response = await fetchWithErrorHandling(url, {
        ...init,
        headers
    });

    return await response.json();
}

async function fetchWithErrorHandling(url, init) {
    const response = await fetch(url, init);

    if (!response.ok) {
        throw new NetworkError('Server responded with an invalid status.', { response });
    }

    return response;
}

function buildAuthorizationHeader(token) {
    if (!token) {
        throw new Error('Unable to build authorization header, token is not set, make sure the user is authenticated.');
    }

    return ['Authorization', `bearer ${token}`];
}

export class NetworkError extends Error {
    response;

    constructor(message, options) {
        super(message, options);
        this.response = options.response;
    }
}
/// --------------------------------------------- keycloak-authz.js------------------------------------------------------------------------------------

var KeycloakAuthorization = function (keycloak, options) {
    var _instance = this;
    this.rpt = null;

    Object.defineProperty(this, 'ready', {
        get() {
            console.warn("The 'ready' property is deprecated and will be removed in a future version. Initialization now happens automatically, using this property is no longer required.");
            return Promise.resolve();
        },
    });
    
    this.init = () => {
        console.warn("The 'init()' method is deprecated and will be removed in a future version. Initialization now happens automatically, calling this method is no longer required.");
    };

    let configPromise;

    async function initializeConfigIfNeeded() {
        if (_instance.config) {
            return _instance.config;
        }

        if (configPromise) {
            return await configPromise;
        }

        if (!keycloak.didInitialize) {
            throw new Error('The Keycloak instance has not been initialized yet.');
        }
        
        configPromise = loadConfig(keycloak.authServerUrl, keycloak.realm);
        _instance.config = await configPromise;
    }

    this.authorize = function (authorizationRequest) {
        this.then = async function (onGrant, onDeny, onError) {
            try {
                await initializeConfigIfNeeded();
            } catch (error) {
                handleError(error, onError);
                return;
            }

            if (authorizationRequest && authorizationRequest.ticket) {
                var request = new XMLHttpRequest();

                request.open('POST', _instance.config.token_endpoint, true);
                request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
                request.setRequestHeader('Authorization', 'Bearer ' + keycloak.token);

                request.onreadystatechange = function () {
                    if (request.readyState == 4) {
                        var status = request.status;

                        if (status >= 200 && status < 300) {
                            var rpt = JSON.parse(request.responseText).access_token;
                            _instance.rpt = rpt;
                            onGrant(rpt);
                        } else if (status == 403) {
                            if (onDeny) {
                                onDeny();
                            } else {
                                console.error('Authorization request was denied by the server.');
                            }
                        } else {
                            if (onError) {
                                onError();
                            } else {
                                console.error('Could not obtain authorization data from server.');
                            }
                        }
                    }
                };

                var params = "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&client_id=" + keycloak.clientId + "&ticket=" + authorizationRequest.ticket;

                if (authorizationRequest.submitRequest != undefined) {
                    params += "&submit_request=" + authorizationRequest.submitRequest;
                }

                var metadata = authorizationRequest.metadata;

                if (metadata) {
                    if (metadata.responseIncludeResourceName) {
                        params += "&response_include_resource_name=" + metadata.responseIncludeResourceName;
                    }
                    if (metadata.responsePermissionsLimit) {
                        params += "&response_permissions_limit=" + metadata.responsePermissionsLimit;
                    }
                }

                if (_instance.rpt && (authorizationRequest.incrementalAuthorization == undefined || authorizationRequest.incrementalAuthorization)) {
                    params += "&rpt=" + _instance.rpt;
                }

                request.send(params);
            }
        };

        return this;
    };

    this.entitlement = function (resourceServerId, authorizationRequest) {
        this.then = async function (onGrant, onDeny, onError) {
            try {
                await initializeConfigIfNeeded();
            } catch (error) {
                handleError(error, onError);
                return;
            }

            var request = new XMLHttpRequest();

            request.open('POST', _instance.config.token_endpoint, true);
            request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
            request.setRequestHeader('Authorization', 'Bearer ' + keycloak.token);

            request.onreadystatechange = function () {
                if (request.readyState == 4) {
                    var status = request.status;

                    if (status >= 200 && status < 300) {
                        var rpt = JSON.parse(request.responseText).access_token;
                        _instance.rpt = rpt;
                        onGrant(rpt);
                    } else if (status == 403) {
                        if (onDeny) {
                            onDeny();
                        } else {
                            console.error('Authorization request was denied by the server.');
                        }
                    } else {
                        if (onError) {
                            onError();
                        } else {
                            console.error('Could not obtain authorization data from server.');
                        }
                    }
                }
            };

            if (!authorizationRequest) {
                authorizationRequest = {};
            }

            var params = "grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&client_id=" + keycloak.clientId;

            if (authorizationRequest.claimToken) {
                params += "&claim_token=" + authorizationRequest.claimToken;

                if (authorizationRequest.claimTokenFormat) {
                    params += "&claim_token_format=" + authorizationRequest.claimTokenFormat;
                }
            }

            params += "&audience=" + resourceServerId;

            var permissions = authorizationRequest.permissions;

            if (!permissions) {
                permissions = [];
            }

            for (var i = 0; i < permissions.length; i++) {
                var resource = permissions[i];
                var permission = resource.id;

                if (resource.scopes && resource.scopes.length > 0) {
                    permission += "#";
                    for (var j = 0; j < resource.scopes.length; j++) {
                        var scope = resource.scopes[j];
                        if (permission.indexOf('#') != permission.length - 1) {
                            permission += ",";
                        }
                        permission += scope;
                    }
                }

                params += "&permission=" + permission;
            }

            var metadata = authorizationRequest.metadata;

            if (metadata) {
                if (metadata.responseIncludeResourceName) {
                    params += "&response_include_resource_name=" + metadata.responseIncludeResourceName;
                }
                if (metadata.responsePermissionsLimit) {
                    params += "&response_permissions_limit=" + metadata.responsePermissionsLimit;
                }
            }

            if (_instance.rpt) {
                params += "&rpt=" + _instance.rpt;
            }

            request.send(params);
        };

        return this;
    };

    return this;
};

async function loadConfig(serverUrl, realm) {
    const url = `${serverUrl}/realms/${encodeURIComponent(realm)}/.well-known/uma2-configuration`;

    try {
        return await fetchJSON(url);
    } catch (error) {
        throw new Error('Could not obtain configuration from server.', { cause: error });
    }
}

async function fetchJSON(url) {
    let response;

    try {
        response = await fetch(url);
    } catch (error) {
        throw new Error('Server did not respond.', { cause: error });
    }

    if (!response.ok) {
        throw new Error('Server responded with an invalid status.');
    }

    try {
        return await response.json();
    } catch (error) {
        throw new Error('Server responded with invalid JSON.', { cause: error });
    }
}

function handleError(error, handler) {
    if (handler) {
        handler(error);
    } else {
        console.error(message, error);
    }
}

export default KeycloakAuthorization;
/// --------------------------------------------- keycloak.d.ts------------------------------------------------------------------------------------
export type KeycloakOnLoad = 'login-required'|'check-sso';
export type KeycloakResponseMode = 'query'|'fragment';
export type KeycloakResponseType = 'code'|'id_token token'|'code id_token token';
export type KeycloakFlow = 'standard'|'implicit'|'hybrid';
export type KeycloakPkceMethod = 'S256' | false;

export interface KeycloakConfig {
	url: string;
	realm: string;
	clientId: string;
}

export interface Acr {
	values: string[];
	essential: boolean;
}

export interface KeycloakInitOptions {
	useNonce?: boolean;

	adapter?: 'default' | 'cordova' | 'cordova-native' | KeycloakAdapter;
	
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

	enableLogging?: boolean

	scope?: string
	
	messageReceiveTimeout?: number

	locale?: string;

	logoutMethod?: 'GET' | 'POST';
}

export interface KeycloakLoginOptions {
	scope?: string;

	redirectUri?: string;

	prompt?: 'none' | 'login' | 'consent';

	action?: string;

	maxAge?: number;

	loginHint?: string;

	acr?: Acr;

	acrValues?: string;

	idpHint?: string;

	locale?: string;

	cordovaOptions?: { [optionName: string]: string };
}

export interface KeycloakLogoutOptions {
	redirectUri?: string;

	logoutMethod?: 'GET' | 'POST';
}

export interface KeycloakRegisterOptions extends Omit<KeycloakLoginOptions, 'action'> { }

export interface KeycloakAccountOptions {
	redirectUri?: string;	
}
export interface KeycloakError {
	error: string;
	error_description: string;
}

export interface KeycloakAdapter {
	login(options?: KeycloakLoginOptions): Promise<void>;
	logout(options?: KeycloakLogoutOptions): Promise<void>;
	register(options?: KeycloakRegisterOptions): Promise<void>;
	accountManagement(): Promise<void>;
	redirectUri(options: { redirectUri: string; }, encodeHash: boolean): string;
}

export interface KeycloakProfile {
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

export interface KeycloakTokenParsed {
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
	realm_access?: KeycloakRoles;
	resource_access?: KeycloakResourceAccess;
	[key: string]: any;
}

export interface KeycloakResourceAccess {
	[key: string]: KeycloakRoles
}

export interface KeycloakRoles {
	roles: string[];
}

export type KeycloakInstance = Keycloak;

declare class Keycloak {
	constructor(config: KeycloakConfig | string)

	authenticated?: boolean;

	subject?: string;

	responseMode?: KeycloakResponseMode;

	responseType?: KeycloakResponseType;

	flow?: KeycloakFlow;

	realmAccess?: KeycloakRoles;

	resourceAccess?: KeycloakResourceAccess;

	token?: string;

	tokenParsed?: KeycloakTokenParsed;

	refreshToken?: string;

	refreshTokenParsed?: KeycloakTokenParsed;

	idToken?: string;

	idTokenParsed?: KeycloakTokenParsed;

	timeSkew?: number;

	didInitialize: boolean;
	
	loginRequired?: boolean;

	authServerUrl?: string;

	realm?: string;

	clientId?: string;

	redirectUri?: string;

	sessionId?: string;

	profile?: KeycloakProfile;

	userInfo?: {};

	onReady?(authenticated?: boolean): void;

	onAuthSuccess?(): void;

	onAuthError?(errorData: KeycloakError): void;

	onAuthRefreshSuccess?(): void;

	onAuthRefreshError?(): void;

	onAuthLogout?(): void;

	onTokenExpired?(): void;

	onActionUpdate?(status: 'success'|'cancelled'|'error', action?: string): void;

	init(initOptions?: KeycloakInitOptions): Promise<boolean>;

	login(options?: KeycloakLoginOptions): Promise<void>;

	logout(options?: KeycloakLogoutOptions): Promise<void>;

	register(options?: KeycloakRegisterOptions): Promise<void>;

	accountManagement(): Promise<void>;

	createLoginUrl(options?: KeycloakLoginOptions): Promise<string>;

	createLogoutUrl(options?: KeycloakLogoutOptions): string;

	createRegisterUrl(options?: KeycloakRegisterOptions): Promise<string>;

	createAccountUrl(options?: KeycloakAccountOptions): string;

	isTokenExpired(minValidity?: number): boolean;

	updateToken(minValidity?: number): Promise<boolean>;

	clearToken(): void;

	hasRealmRole(role: string): boolean;

	hasResourceRole(role: string, resource?: string): boolean;

	loadUserProfile(): Promise<KeycloakProfile>;

	loadUserInfo(): Promise<{}>;
}

export default Keycloak;

export as namespace Keycloak;
/// --------------------------------------------- keycloak-authz.d.ts------------------------------------------------------------------------------------
import Keycloak from './keycloak.js';

export interface KeycloakAuthorizationPromise {
	then(onGrant: (rpt: string) => void, onDeny: () => void, onError: () => void): void;
}

export interface AuthorizationRequest {
	permissions?:ResourcePermission[],

	ticket?:string,

	submitRequest?:boolean,

	metadata?:AuthorizationRequestMetadata,

	incrementalAuthorization?:boolean
}

export interface AuthorizationRequestMetadata {
	responseIncludeResourceName?:any,

	response_permissions_limit?:number
}

export interface ResourcePermission {
	id:string,

	scopes?:string[]
}

export type KeycloakAuthorizationInstance = KeycloakAuthorization;

declare function KeycloakAuthorization(keycloak: Keycloak): KeycloakAuthorization;

declare class KeycloakAuthorization {
	constructor(keycloak: Keycloak)

	rpt: any;
	config: { rpt_endpoint: string };

	init(): void;

	ready: Promise<void>;

	authorize(authorizationRequest: AuthorizationRequest): KeycloakAuthorizationPromise;

	entitlement(resourceServerId: string, authorizationRequest?: AuthorizationRequest): KeycloakAuthorizationPromise;
}

export default KeycloakAuthorization;

export as namespace KeycloakAuthorization;
