import { expect } from '@playwright/test'
import type { KeycloakConfig, KeycloakInitOptions } from '../../lib/keycloak.d.ts'
import { CLIENT_ID } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in and out with default configuration', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)
  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
})

test('logs in and out using a URL to the adapter config', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const configUrl = new URL('/adapter-config.json', appUrl)
  configUrl.searchParams.set('realm', realm)
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  await executor.instantiateAdapter(configUrl.toString())
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  await executor.instantiateAdapter(configUrl.toString())
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  await executor.instantiateAdapter(configUrl.toString())
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
})

test('logs in and out using a generic OpenID provider', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const configOptions: KeycloakConfig = {
    clientId: CLIENT_ID,
    oidcProvider: new URL(`/realms/${realm}`, authServerUrl).toString()
  }
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  await executor.instantiateAdapter(configOptions)
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  await executor.instantiateAdapter(configOptions)
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  await executor.instantiateAdapter(configOptions)
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
})

test('logs in and out without initialization options', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter()).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter()).toBe(true)
  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter()).toBe(false)
})

test('logs in and out without PKCE', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), pkceMethod: false }
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
})

test("logs in and out with 'POST' logout configured at initialization", async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), logoutMethod: 'POST' }
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
})

test("logs in and out with 'POST' logout configured at logout", async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  await executor.logout({ logoutMethod: 'POST' })
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
})

test('logs in and checks session status', async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Trigger login and initialize the adapter to check session status.
  await executor.navigateToApp()
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()
  await executor.initializeAdapter(initOptions)
  // Check if cookies were blocked for the session status iframe.
  expect(executor.consoleMessages().some((message) => message.text().includes('Your browser is blocking access to 3rd-party cookies, this means:'))).toBe(strictCookies)
})

test("logs in and out with onLoad set to 'login-required'", async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    onLoad: 'login-required'
  }
  // Initially, no user should be authenticated, and a redirect to the login page should occur.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions, true)).toBe(false)
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter(initOptions, true)).toBe(false)
})

test("logs in and out with onLoad set to 'check-sso'", async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    onLoad: 'check-sso'
  }
  // Initially, no user should be authenticated, and a redirect should occur in a strict cookie environment.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions, strictCookies)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, no further redirects should occur during initialization, and the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions, false)).toBe(true)
  // Page reloads should not affect the authentication state, and a redirect should occur in all environments.
  await executor.reload()
  expect(await executor.initializeAdapter(initOptions, true)).toBe(true)
})
