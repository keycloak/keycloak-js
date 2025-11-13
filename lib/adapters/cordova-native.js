// @ts-check
/**
 * @import {KeycloakAdapter, KeycloakAdapterContext} from "../keycloak.ts"
 */

/**
 * Cordova Native adapter for Keycloak.
 * Uses the cordova-plugin-safariviewcontroller or cordova-plugin-inappbrowser for authentication.
 * 
 * @param {KeycloakAdapterContext} context - Adapter context provided by the factory
 * @returns {KeycloakAdapter} Adapter implementation
 */
export function createCordovaNativeAdapter(context) {
	const { createLoginUrl, createLogoutUrl, createRegisterUrl, createAccountUrl, clearToken, processCallback, redirectUri } = context;

	// /** @type {any} */
	// let universalLinks;
	// /** @type {any} */
	// let cordovaPluginInAppBrowser;
	// /** @type {any} */
	// let SafariViewController;

	function checkCordovaPluginDependencies() {
		// @ts-ignore - Cordova global
		if (typeof universalLinks === 'undefined' && typeof cordova !== 'undefined' && cordova.plugins && cordova.plugins.browsertab) {
			// @ts-ignore - Cordova plugin
			cordovaPluginInAppBrowser = cordova.plugins.browsertab;
		}

		// @ts-ignore - Cordova global
		if (typeof universalLinks === 'undefined' && typeof SafariViewController === 'undefined') {
			throw new Error("Cordova plugin missing for Cordova native adapter - please install 'cordova-plugin-browsertab', 'cordova-plugin-safariviewcontroller' or 'cordova-plugin-customurlscheme'");
		}
	}

	function handleInAppBrowserCloseEvent() {
		clearToken();
	}

	/**
	 * @param {string} url
	 * @param {string} target
	 * @param {string} options
	 */
	function openBrowserWindow(url, target, options) {
		if (cordovaPluginInAppBrowser) {
			cordovaPluginInAppBrowser.openUrl(url, () => {}, (error) => {
				console.error('Error opening URL: ' + error);
			});
		} else if (SafariViewController) {
			SafariViewController.show({
				url: url
			}, (result) => {
				if (result.event === 'closed') {
					handleInAppBrowserCloseEvent();
				}
			}, (error) => {
				console.error('Error opening Safari View Controller: ' + error);
			});
		}
	}

	return {
		login: async (options) => {
            const loginUrl = await createLoginUrl(options)

            await new Promise((resolve, reject) => {
                universalLinks.subscribe('keycloak', async (event) => {
                    universalLinks.unsubscribe('keycloak')
                    window.cordova.plugins.browsertab.close()

                    try {
                        await processCallback(event.url)
                        resolve()
                    } catch (error) {
                        reject(error)
                    }
                })

                window.cordova.plugins.browsertab.openUrl(loginUrl)
            })
		},
        
		logout: async (options) => {
           const logoutUrl = createLogoutUrl(options)

            await new Promise((resolve) => {
                universalLinks.subscribe('keycloak', () => {
                    universalLinks.unsubscribe('keycloak')
                    window.cordova.plugins.browsertab.close()
                    clearToken()
                    resolve()
                })

                window.cordova.plugins.browsertab.openUrl(logoutUrl)
            })
		},

		register: async (options) => {
            const registerUrl = await createRegisterUrl(options)

            await new Promise((resolve, reject) => {
                universalLinks.subscribe('keycloak', async (event) => {
                    universalLinks.unsubscribe('keycloak')
                    window.cordova.plugins.browsertab.close()

                    try {
                        await this.processCallback(event.url)
                        resolve()
                    } catch (error) {
                        reject(error)
                    }
                })

                window.cordova.plugins.browsertab.openUrl(registerUrl)
            })
		},

		accountManagement: async () => {
            const accountUrl = createAccountUrl()
            if (typeof accountUrl !== 'undefined') {
                window.cordova.plugins.browsertab.openUrl(accountUrl)
            } else {
                throw new Error('Not supported by the OIDC server')
            }
		},

        redirectUri: (options) => {
            if (options && options.redirectUri) {
                return options.redirectUri
            } else if (redirectUri) {
                return redirectUri
            } else {
                return 'http://localhost'
            }
        }
	};
}
