import { expect } from '@playwright/test'
import { AUTHORIZED_USERNAME, CLIENT_ID } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

// Since `createRegisterUrl()` calls `createLoginUrl()` internally, only a small subset of the behavior of `createLoginUrl()` is tested here. All other tests are in the `login-url.spec.ts` file.

test('creates a registration URL with all options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const redirectUri = new URL('/foo/bar', appUrl)
  const registerUrl = new URL(await executor.createRegisterUrl({
    scope: 'openid profile email',
    redirectUri: redirectUri.toString(),
    prompt: 'none',
    maxAge: 3600,
    loginHint: AUTHORIZED_USERNAME,
    idpHint: 'facebook',
    locale: 'nl-NL nl',
    acr: {
      values: ['foo', 'bar'],
      essential: false
    },
    acrValues: '2fa'
  }))
  expect(registerUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/registrations`)
  expect(registerUrl.searchParams.get('client_id')).toBe(CLIENT_ID)
  expect(registerUrl.searchParams.get('redirect_uri')).toBe(redirectUri.toString())
  expect(registerUrl.searchParams.get('state')).toEqual(expect.any(String))
  expect(registerUrl.searchParams.get('response_mode')).toBe('fragment')
  expect(registerUrl.searchParams.get('response_type')).toBe('code')
  expect(registerUrl.searchParams.get('scope')).toBe('openid profile email')
  expect(registerUrl.searchParams.get('nonce')).toEqual(expect.any(String))
  expect(registerUrl.searchParams.get('prompt')).toBe('none')
  expect(registerUrl.searchParams.get('max_age')).toBe('3600')
  expect(registerUrl.searchParams.get('login_hint')).toBe(AUTHORIZED_USERNAME)
  expect(registerUrl.searchParams.get('kc_idp_hint')).toBe('facebook')
  expect(registerUrl.searchParams.get('kc_action')).toBeNull()
  expect(registerUrl.searchParams.get('ui_locales')).toBe('nl-NL nl')
  expect(registerUrl.searchParams.get('claims')).toBe('{"id_token":{"acr":{"values":["foo","bar"],"essential":false}}}')
  expect(registerUrl.searchParams.get('acr_values')).toBe('2fa')
  expect(registerUrl.searchParams.get('code_challenge')).toEqual(expect.any(String))
  expect(registerUrl.searchParams.get('code_challenge_method')).toBe('S256')
})

test('creates a registration URL with default options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const registerUrl = new URL(await executor.createRegisterUrl())
  expect(registerUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/registrations`)
  expect(registerUrl.searchParams.get('client_id')).toBe(CLIENT_ID)
  expect(registerUrl.searchParams.get('redirect_uri')).toBe(appUrl.toString())
  expect(registerUrl.searchParams.get('state')).toEqual(expect.any(String))
  expect(registerUrl.searchParams.get('response_mode')).toBe('fragment')
  expect(registerUrl.searchParams.get('response_type')).toBe('code')
  expect(registerUrl.searchParams.get('scope')).toBe('openid')
  expect(registerUrl.searchParams.get('nonce')).toEqual(expect.any(String))
  expect(registerUrl.searchParams.get('prompt')).toBeNull()
  expect(registerUrl.searchParams.get('max_age')).toBeNull()
  expect(registerUrl.searchParams.get('login_hint')).toBeNull()
  expect(registerUrl.searchParams.get('kc_idp_hint')).toBeNull()
  expect(registerUrl.searchParams.get('kc_action')).toBeNull()
  expect(registerUrl.searchParams.get('ui_locales')).toBeNull()
  expect(registerUrl.searchParams.get('claims')).toBeNull()
  expect(registerUrl.searchParams.get('acr_values')).toBeNull()
  expect(registerUrl.searchParams.get('code_challenge')).toEqual(expect.any(String))
  expect(registerUrl.searchParams.get('code_challenge_method')).toBe('S256')
})
