import { expect } from '@playwright/test'
import type { KeycloakConfig } from '../../lib/keycloak.js'
import { AUTHORIZED_USERNAME, CLIENT_ID } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('loads the user profile', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated and loading the user profile should fail.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await expect(executor.loadUserProfile()).rejects.toThrow('Unable to build authorization header, token is not set, make sure the user is authenticated.')
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated and loading the user profile should succeed.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.profile()).toBeUndefined()
  expect(await executor.loadUserProfile()).toMatchObject({ username: AUTHORIZED_USERNAME })
  expect(await executor.profile()).toMatchObject({ username: AUTHORIZED_USERNAME })
})

test('throws loading the user profile using a generic OpenID provider', async ({ page, appUrl, authServerUrl }) => {
  const { executor, realm } = await createTestBed(page, { appUrl, authServerUrl })
  const configOptions: KeycloakConfig = {
    clientId: CLIENT_ID,
    oidcProvider: new URL(`/realms/${realm}`, authServerUrl).toString()
  }
  const initOptions = executor.defaultInitOptions()
  await executor.navigateToApp()
  await executor.instantiateAdapter(configOptions)
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()
  await executor.instantiateAdapter(configOptions)
  await executor.initializeAdapter(initOptions)
  await expect(executor.loadUserProfile()).rejects.toThrow('Unable to load user profile, make sure the adapter is not configured using a generic OIDC provider.')
})
