import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.d.ts'
import { AUTHORIZED_USERNAME, CLIENT_ID } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('creates a login URL with all options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const redirectUri = new URL('/foo/bar', appUrl)
  const loginUrl = new URL(await executor.createLoginUrl({
    scope: 'openid profile email',
    redirectUri: redirectUri.toString(),
    prompt: 'none',
    maxAge: 3600,
    loginHint: AUTHORIZED_USERNAME,
    idpHint: 'facebook',
    action: 'UPDATE_PASSWORD',
    locale: 'nl-NL nl',
    acr: {
      values: ['foo', 'bar'],
      essential: false
    },
    acrValues: '2fa'
  }))
  expect(loginUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/auth`)
  expect(loginUrl.searchParams.get('client_id')).toBe(CLIENT_ID)
  expect(loginUrl.searchParams.get('redirect_uri')).toBe(redirectUri.toString())
  expect(loginUrl.searchParams.get('state')).toEqual(expect.any(String))
  expect(loginUrl.searchParams.get('response_mode')).toBe('fragment')
  expect(loginUrl.searchParams.get('response_type')).toBe('code')
  expect(loginUrl.searchParams.get('scope')).toBe('openid profile email')
  expect(loginUrl.searchParams.get('nonce')).toEqual(expect.any(String))
  expect(loginUrl.searchParams.get('prompt')).toBe('none')
  expect(loginUrl.searchParams.get('max_age')).toBe('3600')
  expect(loginUrl.searchParams.get('login_hint')).toBe(AUTHORIZED_USERNAME)
  expect(loginUrl.searchParams.get('kc_idp_hint')).toBe('facebook')
  expect(loginUrl.searchParams.get('kc_action')).toBe('UPDATE_PASSWORD')
  expect(loginUrl.searchParams.get('ui_locales')).toBe('nl-NL nl')
  expect(loginUrl.searchParams.get('claims')).toBe('{"id_token":{"acr":{"values":["foo","bar"],"essential":false}}}')
  expect(loginUrl.searchParams.get('acr_values')).toBe('2fa')
  expect(loginUrl.searchParams.get('code_challenge')).toEqual(expect.any(String))
  expect(loginUrl.searchParams.get('code_challenge_method')).toBe('S256')
})

test('creates a login URL with default options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const loginUrl = new URL(await executor.createLoginUrl())
  expect(loginUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/auth`)
  expect(loginUrl.searchParams.get('client_id')).toBe(CLIENT_ID)
  expect(loginUrl.searchParams.get('redirect_uri')).toBe(appUrl.toString())
  expect(loginUrl.searchParams.get('state')).toEqual(expect.any(String))
  expect(loginUrl.searchParams.get('response_mode')).toBe('fragment')
  expect(loginUrl.searchParams.get('response_type')).toBe('code')
  expect(loginUrl.searchParams.get('scope')).toBe('openid')
  expect(loginUrl.searchParams.get('nonce')).toEqual(expect.any(String))
  expect(loginUrl.searchParams.get('prompt')).toBeNull()
  expect(loginUrl.searchParams.get('max_age')).toBeNull()
  expect(loginUrl.searchParams.get('login_hint')).toBeNull()
  expect(loginUrl.searchParams.get('kc_idp_hint')).toBeNull()
  expect(loginUrl.searchParams.get('kc_action')).toBeNull()
  expect(loginUrl.searchParams.get('ui_locales')).toBeNull()
  expect(loginUrl.searchParams.get('claims')).toBeNull()
  expect(loginUrl.searchParams.get('acr_values')).toBeNull()
  expect(loginUrl.searchParams.get('code_challenge')).toEqual(expect.any(String))
  expect(loginUrl.searchParams.get('code_challenge_method')).toBe('S256')
})

test('creates a login URL to the registration page', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const loginUrl = new URL(await executor.createLoginUrl({ action: 'register' }))
  expect(loginUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/registrations`)
  expect(loginUrl.searchParams.get('kc_action')).toBeNull()
})

test('creates a login URL using the redirect URL passed during initialization', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const redirectUri = new URL('/foo/bar', appUrl)
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), redirectUri: redirectUri.toString() }
  await executor.initializeAdapter(initOptions)
  const loginUrl = new URL(await executor.createLoginUrl())
  expect(loginUrl.searchParams.get('redirect_uri')).toBe(redirectUri.toString())
})

test('creates a login URL using the scope passed during initialization', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), scope: 'openid profile email' }
  await executor.initializeAdapter(initOptions)
  const loginUrl = new URL(await executor.createLoginUrl())
  expect(loginUrl.searchParams.get('scope')).toBe('openid profile email')
})

test("creates a login URL with the 'openid' scope appended if omitted", async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), scope: 'profile email openidlike' }
  await executor.initializeAdapter(initOptions)
  const loginUrl = new URL(await executor.createLoginUrl())
  expect(loginUrl.searchParams.get('scope')).toBe('openid profile email openidlike')
})

test('creates a login URL using the response mode passed during initialization', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), responseMode: 'query' }
  await executor.initializeAdapter(initOptions)
  const loginUrl = new URL(await executor.createLoginUrl())
  expect(loginUrl.searchParams.get('response_mode')).toBe('query')
})

test('creates a login URL based on the flow passed during initialization', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), flow: 'implicit' }
  await executor.initializeAdapter(initOptions)
  const loginUrl = new URL(await executor.createLoginUrl())
  expect(loginUrl.searchParams.get('response_type')).toBe('id_token token')
})

test('creates a login URL with a max age of 0', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const loginUrl = new URL(await executor.createLoginUrl({ maxAge: 0 }))
  expect(loginUrl.searchParams.get('max_age')).toBe('0')
})
