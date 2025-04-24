import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.d.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in with a silent SSO redirect', async ({ page, appUrl, authServerUrl, strictCookies }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
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
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
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
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
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
