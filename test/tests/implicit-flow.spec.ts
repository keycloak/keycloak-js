import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.js'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in with an implicit flow', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  const implicitFlow: KeycloakInitOptions = { ...executor.defaultInitOptions(), flow: 'implicit' }
  const standardFlow: KeycloakInitOptions = { ...executor.defaultInitOptions(), flow: 'standard' }
  // Initially, no user should be authenticated, and login should fail as implicit flow is disabled.
  expect(await executor.initializeAdapter(implicitFlow)).toBe(false)
  await executor.login()
  await expect(executor.initializeAdapter(implicitFlow)).rejects.toMatchObject({
    error: 'unauthorized_client',
    error_description: 'Client+is+not+allowed+to+initiate+browser+login+with+given+response_type.+Implicit+flow+is+disabled+for+the+client.'
  })
  // After enabling implicit flow, authenticating with the standard flow should fail.
  await updateClient({ implicitFlowEnabled: true, standardFlowEnabled: false })
  await executor.reload()
  expect(await executor.initializeAdapter(standardFlow)).toBe(false)
  await executor.login()
  await expect(executor.initializeAdapter(standardFlow)).rejects.toMatchObject({
    error: 'unauthorized_client',
    error_description: 'Client+is+not+allowed+to+initiate+browser+login+with+given+response_type.+Standard+flow+is+disabled+for+the+client.'
  })
  // Now that the implicit flow is enabled, the user should be able to authenticate successfully.
  await executor.reload()
  expect(await executor.initializeAdapter(implicitFlow)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(implicitFlow)).toBe(true)
})

test('does not allow query response mode with an implicit flow', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    flow: 'implicit',
    responseMode: 'query'
  }
  await updateClient({ implicitFlowEnabled: true, standardFlowEnabled: false })
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  // Attempting to log in should fail with an error indicating that the query response mode is not allowed for implicit flow.
  await executor.login()
  await expect(executor.initializeAdapter(initOptions)).rejects.toMatchObject({
    error: 'invalid_request',
    error_description: 'Response_mode+%27query%27+not+allowed+for+implicit+or+hybrid+flow'
  })
})

test('fails refreshing a token for an implicit flow', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    flow: 'implicit'
  }
  await updateClient({ implicitFlowEnabled: true, standardFlowEnabled: false })
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After logging in, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  // Attempting to refresh the token should fail with an error indicating that the implicit flow does not support refreshing tokens.
  await expect(executor.updateToken(9999)).rejects.toThrow()
})

test('expires the access token with an implicit flow', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateRealm, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await updateRealm({ accessTokenLifespanForImplicitFlow: 3 })
  await updateClient({ implicitFlowEnabled: true, standardFlowEnabled: false })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    flow: 'implicit'
  }
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After logging in, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  // The token should not be expired yet.
  expect(await executor.isTokenExpired()).toBe(false)
  // After waiting for 5 seconds, the token should be expired.
  await executor.addTimeSkew(-5)
  expect(await executor.isTokenExpired()).toBe(true)
})
