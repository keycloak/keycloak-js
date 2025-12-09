import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.d.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in and obtains scopes passed in during initialization', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    onLoad: 'login-required',
    scope: 'openid profile email phone'
  }
  // Initially, no user should be authenticated, and a redirect to the login page should occur.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions, true)).toBe(false)
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated, and the provided scopes should be present.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  const tokenParsed = await executor.tokenParsed()
  expect(tokenParsed?.scope).toContain('openid')
  expect(tokenParsed?.scope).toContain('profile')
  expect(tokenParsed?.scope).toContain('email')
  expect(tokenParsed?.scope).toContain('phone')
})

test('logs in and obtains scopes passed in during login', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login({
    scope: 'openid profile email phone'
  })
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated, and the provided scopes should be present.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  const tokenParsed = await executor.tokenParsed()
  expect(tokenParsed?.scope).toContain('openid')
  expect(tokenParsed?.scope).toContain('profile')
  expect(tokenParsed?.scope).toContain('email')
  expect(tokenParsed?.scope).toContain('phone')
})
