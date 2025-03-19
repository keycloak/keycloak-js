import type { Page } from 'playwright'
import type Keycloak from '../../lib/keycloak.d.ts'
import type { KeycloakConfig, KeycloakInitOptions, KeycloakLoginOptions, KeycloakLogoutOptions } from '../../lib/keycloak.d.ts'
import { APP_HOST, AUTH_SERVER_HOST, AUTHORIZED_PASSWORD, AUTHORIZED_USERNAME, CLIENT_ID } from './common.ts'

export class TestExecutor {
  readonly #page: Page
  readonly #realm: string

  constructor (page: Page, realm: string) {
    this.#page = page
    this.#realm = realm
  }

  async instantiateAdapter (config: KeycloakConfig = { url: AUTH_SERVER_HOST, realm: this.#realm, clientId: CLIENT_ID }): Promise<void> {
    await this.#ensureOnAppPage()
    await this.#page.evaluate((config) => {
      (globalThis as any).keycloak = new (globalThis as any).Keycloak(config)
    }, config)
  }

  async initializeAdapter (options: KeycloakInitOptions = { onLoad: 'check-sso' }): Promise<boolean> {
    await this.#ensureOnAppPage()
    await this.#ensureInstantiated()

    let result
    try {
      // Because `.evaluate()` can throw an error if a navigation occurs, we need to capture the result
      // to differentiate between the error thrown by the adapter and the error thrown by an unexpected navigation.
      result = await this.#page.evaluate(async (options) => {
        try {
          const value = await ((globalThis as any).keycloak as Keycloak).init(options)
          return { value, error: null }
        } catch (error) {
          return { value: null, error }
        }
      }, options)
    } catch {
      // The only reason an error is thrown here is because the page navigated, which is expected and can be ignored.
      result = { value: null, error: null }
    }

    if (result.error !== null) {
      // The error is not related to the navigation, so we need to throw it.
      throw result.error as Error
    }

    return result.value ?? false
  }

  async submitLoginForm (username = AUTHORIZED_USERNAME, password = AUTHORIZED_PASSWORD): Promise<void> {
    await this.#page.getByRole('textbox', { name: 'Username or email' }).fill(username)
    await this.#page.getByRole('textbox', { name: 'Password' }).fill(password)
    await this.#page.getByRole('button', { name: 'Sign In' }).click()
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

    await this.#waitForLoginPage()
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

    await this.#waitForAppPage()
  }

  async #ensureOnAppPage (): Promise<void> {
    if (!this.#page.url().startsWith(APP_HOST)) {
      await this.#page.goto(APP_HOST)
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
        return ((globalThis as any).keycloak as Keycloak | null) !== null
      })
    } catch {
      return false
    }
  }

  async #waitForAppPage (): Promise<void> {
    await this.#page.waitForURL(APP_HOST + '/**')
  }

  async #waitForLoginPage (): Promise<void> {
    await this.#page.waitForURL(AUTH_SERVER_HOST + '/**')
  }
}
