import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.js'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in and out', async ({ page, appUrl, authServerUrl }) => {
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated.
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

test('logs in and out without initialization options', async ({ page, appUrl, authServerUrl }) => {
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  // Initially, no user should be authenticated.
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
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), pkceMethod: false }
  // Initially, no user should be authenticated.
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
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), logoutMethod: 'POST' }
  // Initially, no user should be authenticated.
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
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  await executor.logout({ logoutMethod: 'POST' })
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
})

test('logs in with a silent SSO redirect', async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    onLoad: 'check-sso',
    silentCheckSsoRedirectUri: executor.silentSSORedirectUrl().toString()
  }
  // Initially, no user should be authenticated, and a redirect should occur in a strict cookie environment.
  expect(await executor.initializeAdapter(initOptions, strictCookies)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, no further redirects should occur during initialization, and the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions, false)).toBe(true)
  // Page reloads should not affect the authentication state, and a redirect should occur in a strict cookie environment.
  await executor.reload()
  expect(await executor.initializeAdapter(initOptions, strictCookies)).toBe(true)
})

test('logs in with a silent SSO redirect and login iframe disabled', async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    onLoad: 'check-sso',
    silentCheckSsoRedirectUri: executor.silentSSORedirectUrl().toString(),
    checkLoginIframe: false
  }
  // Initially, no user should be authenticated, and a redirect should occur in a strict cookie environment.
  expect(await executor.initializeAdapter(initOptions, strictCookies)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, no further redirects should occur during initialization, and the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions, false)).toBe(true)
  // Page reloads should not affect the authentication state, and a redirect should occur in a strict cookie environment.
  await executor.reload()
  expect(await executor.initializeAdapter(initOptions, strictCookies)).toBe(true)
})

test('logs in with a silent SSO redirect and fallback disabled', async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    onLoad: 'check-sso',
    silentCheckSsoRedirectUri: executor.silentSSORedirectUrl().toString(),
    silentCheckSsoFallback: false
  }
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  // With fallback disabled, a redirect to the authentication server should not occur, leading to an unauthenticated state when strict cookies are enabled.
  await executor.reload()
  expect(await executor.initializeAdapter(initOptions)).toBe(!strictCookies)
})

test('logs in with a silent SSO redirect without an iframe configured', async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    onLoad: 'check-sso'
  }
  // Initially, no user should be authenticated, and a redirect should occur in a strict cookie environment.
  expect(await executor.initializeAdapter(initOptions, strictCookies)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, no further redirects should occur during initialization, and the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions, false)).toBe(true)
  // Page reloads should not affect the authentication state, and a redirect should occur in all environments.
  await executor.reload()
  expect(await executor.initializeAdapter(initOptions, true)).toBe(true)
})

test('logs in and checks session status', async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const executor = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Trigger login and initialize the adapter to check session status.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()
  await executor.initializeAdapter(initOptions)
  // Check if cookies were blocked for the session status iframe.
  expect(executor.consoleMessages().some((message) => message.text().includes('Your browser is blocking access to 3rd-party cookies, this means:'))).toBe(strictCookies)
})
