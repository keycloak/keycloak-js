import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.js'
import { CLIENT_ID } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('creates a logout URL with all options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const redirectUri = new URL('/foo/bar', appUrl)
  const logoutUrl = new URL(await executor.createLogoutUrl({
    logoutMethod: 'GET',
    redirectUri: redirectUri.toString()
  }))
  expect(logoutUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/logout`)
  expect(logoutUrl.searchParams.get('client_id')).toBe(CLIENT_ID)
  expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(redirectUri.toString())
  expect(logoutUrl.searchParams.get('id_token_hint')).toBeNull()
})

test('creates a logout URL with default options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const logoutUrl = new URL(await executor.createLogoutUrl())
  expect(logoutUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/logout`)
  expect(logoutUrl.searchParams.get('client_id')).toBe(CLIENT_ID)
  expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(appUrl.toString())
  expect(logoutUrl.searchParams.get('id_token_hint')).toBeNull()
})

test("creates a logout URL with 'POST' method", async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter(executor.defaultInitOptions())
  const redirectUri = new URL('/foo/bar', appUrl)
  const logoutUrl = new URL(await executor.createLogoutUrl({
    logoutMethod: 'POST',
    redirectUri: redirectUri.toString()
  }))
  expect(logoutUrl.pathname).toBe(`/realms/${realm}/protocol/openid-connect/logout`)
  expect(logoutUrl.searchParams.get('client_id')).toBeNull()
  expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBeNull()
  expect(logoutUrl.searchParams.get('id_token_hint')).toBeNull()
})

test('creates a logout URL using the redirect URL passed during initialization', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const redirectUri = new URL('/foo/bar', appUrl)
  const initOptions: KeycloakInitOptions = { ...executor.defaultInitOptions(), redirectUri: redirectUri.toString() }
  await executor.initializeAdapter(initOptions)
  const logoutUrl = new URL(await executor.createLogoutUrl())
  expect(logoutUrl.searchParams.get('post_logout_redirect_uri')).toBe(redirectUri.toString())
})

test('creates a logout URL with the ID token hint when authenticated', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter()
  await executor.login()
  await executor.submitLoginForm()
  await executor.initializeAdapter()
  const logoutUrl = new URL(await executor.createLogoutUrl())
  expect(logoutUrl.searchParams.get('id_token_hint')).toEqual(expect.any(String))
})
