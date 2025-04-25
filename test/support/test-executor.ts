import type { ConsoleMessage, Page } from 'playwright'
import type Keycloak from '../../lib/keycloak.d.ts'
import type { KeycloakConfig, KeycloakInitOptions, KeycloakLoginOptions, KeycloakLogoutOptions, KeycloakProfile, KeycloakTokenParsed } from '../../lib/keycloak.d.ts'
import { AUTHORIZED_PASSWORD, AUTHORIZED_USERNAME, CLIENT_ID } from './common.ts'
import type { TestOptions } from './testbed.ts'

interface ValueResult<T> {
  value: T
}

interface ErrorResult {
  error: Error
}

type Result<T> = ValueResult<T> | ErrorResult

function isErrorResult<T> (result: Result<T>): result is ErrorResult {
  return 'error' in result
}

export type TestExecutorOptions = Pick<TestOptions, 'appUrl' | 'authServerUrl'>

export class TestExecutor {
  readonly #page: Page
  readonly #realm: string
  readonly #options: TestExecutorOptions
  #consoleMessages: ConsoleMessage[] = []

  constructor (page: Page, realm: string, options: TestExecutorOptions) {
    this.#page = page
    this.#realm = realm
    this.#options = options

    // Intercept all console messages.
    this.#page.on('console', (message) => {
      this.#consoleMessages.push(message)
    })
  }

  async instantiateAdapter (config: KeycloakConfig = this.defaultConfig()): Promise<void> {
    // Reset the console messages when instantiating the adapter.
    this.#consoleMessages = []
    await this.#ensureOnAppPage()
    // Wait for the Keycloak constructor to be exposed globally by the app.
    // Sometimes the script that does so is not executed yet, so we need to wait for it.
    await this.#page.waitForFunction(() => 'Keycloak' in globalThis)
    await this.#page.evaluate((config) => {
      (globalThis as any).keycloak = new (globalThis as any).Keycloak(config)
    }, config)
  }

  defaultConfig (): KeycloakConfig {
    return {
      url: this.#options.authServerUrl.toString(),
      realm: this.#realm,
      clientId: CLIENT_ID
    }
  }

  async initializeAdapter (options?: KeycloakInitOptions, shouldRedirect = false): Promise<boolean> {
    await this.#ensureInstantiated()

    let result: Result<boolean>
    try {
      // Because `.evaluate()` can throw an error if a navigation occurs, we need to capture the result
      // to differentiate between the error thrown by the adapter and the error thrown by an unexpected navigation.
      result = await this.#page.evaluate(async (options) => {
        try {
          const value = await ((globalThis as any).keycloak as Keycloak).init(options)
          return { value }
        } catch (error) {
          return { error: error as Error }
        }
      }, options)

      if (shouldRedirect) {
        throw new Error('Expected a redirect to occur during initialization, but it did not.')
      }
    } catch {
      // The only reason an error is caught here is because the page navigated.
      if (!shouldRedirect) {
        throw new Error('Did not expect a redirect to occur during initialization, but it did.')
      }

      // When login-required is set, the page will redirect to the login page.
      // Therefore, re-initializing the adapter can be skipped and we can assume the user is not authenticated.
      if (options?.onLoad === 'login-required') {
        return false
      }

      // We need to re-initialize the adapter after being redirected back to the app.
      return await this.initializeAdapter(options)
    }

    if (isErrorResult(result)) {
      // The error is not related to the navigation, so we need to throw it.
      throw result.error
    }

    return result.value
  }

  defaultInitOptions (): KeycloakInitOptions {
    return {
      enableLogging: true
    }
  }

  silentSSORedirectUrl (): URL {
    return new URL('./silent-check-sso.html', this.#options.appUrl)
  }

  consoleMessages (): ConsoleMessage[] {
    return this.#consoleMessages
  }

  async submitLoginForm (username = AUTHORIZED_USERNAME, password = AUTHORIZED_PASSWORD): Promise<void> {
    await this.#page.getByRole('textbox', { name: 'Username or email' }).fill(username)
    await this.#page.getByRole('textbox', { name: 'Password' }).fill(password)
    await this.#page.getByRole('button', { name: 'Sign In' }).click()
  }

  async createLoginUrl (options?: KeycloakLoginOptions): Promise<string> {
    await this.#assertInstantiated()
    return await this.#page.evaluate(async (options) => {
      return await ((globalThis as any).keycloak as Keycloak).createLoginUrl(options)
    }, options)
  }

  async createLogoutUrl (options?: KeycloakLogoutOptions): Promise<string> {
    await this.#assertInstantiated()
    return await this.#page.evaluate(async (options) => {
      return ((globalThis as any).keycloak as Keycloak).createLogoutUrl(options)
    }, options)
  }

  async login (options?: KeycloakLoginOptions): Promise<void> {
    await this.#assertInstantiated()

    let result
    try {
      // Because `.evaluate()` can throw an error if a navigation occurs, we need to capture the result
      // to differentiate between the error thrown by the adapter and the error thrown by an unexpected navigation.
      result = await this.#page.evaluate(async (options) => {
        try {
          await ((globalThis as any).keycloak as Keycloak).login(options)
          return { error: null }
        } catch (error) {
          return { error }
        }
      }, options)
    } catch {
      // The only reason an error is thrown here is because the page navigated, which is expected and can be ignored.
      result = { error: null }
    }

    if (result.error !== null) {
      // The error is not related to the navigation, so we need to throw it.
      throw result.error as Error
    }
  }

  async logout (options?: KeycloakLogoutOptions): Promise<void> {
    await this.#assertInstantiated()

    let result
    try {
      // Because `.evaluate()` can throw an error if a navigation occurs, we need to capture the result
      // to differentiate between the error thrown by the adapter and the error thrown by an unexpected navigation.
      result = await this.#page.evaluate(async (options) => {
        try {
          await ((globalThis as any).keycloak as Keycloak).logout(options)
          return { error: null }
        } catch (error) {
          return { error }
        }
      }, options)
    } catch {
      // The only reason an error is thrown here is because the page navigated, which is expected and can be ignored.
      result = { error: null }
    }

    if (result.error !== null) {
      // The error is not related to the navigation, so we need to throw it.
      throw result.error as Error
    }

    await this.#page.waitForNavigation()
  }

  async updateToken (minValidity?: number): Promise<boolean> {
    await this.#assertInstantiated()
    return await this.#page.evaluate(async (minValidity) => {
      return await ((globalThis as any).keycloak as Keycloak).updateToken(minValidity)
    }, minValidity)
  }

  async addTimeSkew (addition: number): Promise<void> {
    await this.#assertInstantiated()
    await this.#page.evaluate((addition) => {
      (((globalThis as any).keycloak as Keycloak).timeSkew as number) += addition
    }, addition)
  }

  async loadUserProfile (): Promise<KeycloakProfile> {
    await this.#assertInstantiated()
    return await this.#page.evaluate(async () => {
      return await ((globalThis as any).keycloak as Keycloak).loadUserProfile()
    })
  }

  async isAuthenticated (): Promise<boolean> {
    await this.#assertInstantiated()
    return await this.#page.evaluate(() => {
      return ((globalThis as any).keycloak as Keycloak).authenticated as boolean
    })
  }

  async isTokenExpired (minValidity?: number): Promise<boolean> {
    await this.#assertInstantiated()
    return await this.#page.evaluate((minValidity) => {
      return ((globalThis as any).keycloak as Keycloak).isTokenExpired(minValidity)
    }, minValidity)
  }

  async tokenParsed (): Promise<KeycloakTokenParsed | undefined> {
    await this.#assertInstantiated()
    return await this.#page.evaluate(() => {
      return ((globalThis as any).keycloak as Keycloak).tokenParsed
    })
  }

  async reload (): Promise<void> {
    await this.#page.reload()
  }

  async #ensureOnAppPage (): Promise<void> {
    if (!this.#page.url().startsWith(this.#options.appUrl.origin)) {
      await this.#page.goto(this.#options.appUrl.toString())
    }
  }

  async #ensureInstantiated (): Promise<void> {
    if (!await this.#isInstantiated()) {
      await this.instantiateAdapter()
    }
  }

  async #assertInstantiated (): Promise<void> {
    if (!await this.#isInstantiated()) {
      throw new Error('The adapter is not instantiated, make sure the adapter is instantiated before calling this method.')
    }
  }

  async #isInstantiated (): Promise<boolean> {
    try {
      return await this.#page.evaluate(() => {
        return ((globalThis as any).keycloak as Keycloak | undefined) !== undefined
      })
    } catch {
      return false
    }
  }
}
