import { expect } from '@playwright/test'
import { CLIENT_ID } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('creates an account URL with all options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.navigateToApp()
  await executor.initializeAdapter(executor.defaultInitOptions())
  const redirectUri = new URL('/foo/bar', appUrl)
  const accountUrl = new URL(await executor.createAccountUrl({
    redirectUri: redirectUri.toString()
  }))
  expect(accountUrl.pathname).toBe(`/realms/${realm}/account`)
  expect(accountUrl.searchParams.get('referrer')).toBe(CLIENT_ID)
  expect(accountUrl.searchParams.get('referrer_uri')).toBe(redirectUri.toString())
})

test('creates an account URL with default options', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.navigateToApp()
  await executor.initializeAdapter(executor.defaultInitOptions())
  const accountUrl = new URL(await executor.createAccountUrl())
  expect(accountUrl.pathname).toBe(`/realms/${realm}/account`)
  expect(accountUrl.searchParams.get('referrer')).toBe(CLIENT_ID)
  expect(accountUrl.searchParams.get('referrer_uri')).toBe(appUrl.toString())
})

test('throws creating an account URL using a generic OpenID provider', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  const oidcProviderUrl = new URL(`/realms/${realm}`, authServerUrl)
  await executor.navigateToApp()
  await executor.instantiateAdapter({
    clientId: CLIENT_ID,
    oidcProvider: oidcProviderUrl.toString()
  })
  await executor.initializeAdapter(executor.defaultInitOptions())
  await expect(executor.createAccountUrl()).rejects.toThrow('Unable to create account URL, make sure the adapter is not configured using a generic OIDC provider.')
})
