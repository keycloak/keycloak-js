// @ts-check
/**
 * @import {KeycloakAdapter, KeycloakAdapterContext, KeycloakLoginOptions, KeycloakLogoutOptions, KeycloakRegisterOptions} from "../keycloak.ts"
 */

/**
 * @typedef {Object} CordovaEvent
 * @property {string} url
 */

/**
 * Cordova adapter factory function
 * @param {KeycloakAdapterContext} context
 * @returns {KeycloakAdapter}
 */
export function createCordovaAdapter(context) {
  /**
   * @param {string} loginUrl
   * @param {string} target
   * @param {string} options
   * @returns {any}
   */
  const cordovaOpenWindowWrapper = (loginUrl, target, options) => {
    if (window.cordova && window.cordova.InAppBrowser) {
      // Use inappbrowser for IOS and Android if available
      return window.cordova.InAppBrowser.open(loginUrl, target, options)
    } else {
      return window.open(loginUrl, target, options)
    }
  }

  const shallowCloneCordovaOptions = (userOptions) => {
    if (userOptions && userOptions.cordovaOptions) {
      return Object.keys(userOptions.cordovaOptions).reduce((options, optionName) => {
        options[optionName] = userOptions.cordovaOptions[optionName]
        return options
      }, {})
    } else {
      return {}
    }
  }

  const formatCordovaOptions = (cordovaOptions) => {
    return Object.keys(cordovaOptions).reduce((options, optionName) => {
      options.push(optionName + '=' + cordovaOptions[optionName])
      return options
    }, []).join(',')
  }

  const createCordovaOptions = (userOptions) => {
    const cordovaOptions = shallowCloneCordovaOptions(userOptions)
    cordovaOptions.location = 'no'
    if (userOptions && userOptions.prompt === 'none') {
      cordovaOptions.hidden = 'yes'
    }
    return formatCordovaOptions(cordovaOptions)
  }

  const getCordovaRedirectUri = () => {
    return context.redirectUri || 'http://localhost'
  }

  return {
    login: async (options) => {
      const cordovaOptions = createCordovaOptions(options)
      const loginUrl = await context.createLoginUrl(options)
      const ref = cordovaOpenWindowWrapper(loginUrl, '_blank', cordovaOptions)
      let completed = false
      let closed = false

      function closeBrowser () {
        closed = true
        ref.close()
      };

      return await new Promise((resolve, reject) => {
        ref.addEventListener('loadstart', async (event) => {
          if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
            try {
              await context.processCallback(event.url)
              resolve(undefined)
            } catch (error) {
              reject(error)
            }
            closeBrowser()
            completed = true
          }
        })

        ref.addEventListener('loaderror', async (event) => {
          if (!completed) {
            if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
              try {
                await context.processCallback(event.url)
                resolve(undefined)
              } catch (error) {
                reject(error)
              }
              closeBrowser()
              completed = true
            } else {
              reject(new Error('Unable to process login.'))
              closeBrowser()
            }
          }
        })

        ref.addEventListener('exit', function (/** @type {any} */ event) {
          if (!closed) {
            reject(new Error('User closed the login window.'))
          }
        })
      })
    },

    logout: async (options) => {
      const logoutUrl = context.createLogoutUrl(options)
      const ref = cordovaOpenWindowWrapper(logoutUrl, '_blank', 'location=no,hidden=yes,clearcache=yes')
      let error = false

      ref.addEventListener('loadstart', (event) => {
        if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
          ref.close()
        }
      })

      ref.addEventListener('loaderror', (event) => {
        if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
          ref.close()
        } else {
          error = true
          ref.close()
        }
      })

      await new Promise((resolve, reject) => {
        ref.addEventListener('exit', () => {
          if (error) {
            reject(new Error('User closed the login window.'))
          } else {
            context.clearToken()
            resolve(undefined)
          }
        })
      })
    },

    register: async (options) => {
      const registerUrl = await context.createRegisterUrl()
      const cordovaOptions = createCordovaOptions(options)
      const ref = cordovaOpenWindowWrapper(registerUrl, '_blank', cordovaOptions)

      /** @type {Promise<void>} */
      const promise = new Promise((resolve, reject) => {
        ref.addEventListener('loadstart', async (event) => {
          if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
            ref.close()

            try {
              await context.processCallback(event.url)
              resolve(undefined)
            } catch (error) {
              reject(error)
            }
          }
        })
      })

      await promise
    },

    accountManagement: async () => {
      const accountUrl = context.createAccountUrl()
      if (typeof accountUrl !== 'undefined') {
        const ref = cordovaOpenWindowWrapper(accountUrl, '_blank', 'location=no')
        ref.addEventListener('loadstart', function (event) {
          if (event.url.indexOf(getCordovaRedirectUri()) === 0) {
            ref.close()
          }
        })
      } else {
        throw new Error('Not supported by the OIDC server')
      }
    },

    redirectUri: () => {
      return getCordovaRedirectUri()
    }
  }
}
