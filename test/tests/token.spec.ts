import { expect } from '@playwright/test'
import { createTestBed, test } from '../support/testbed.ts'

test('refreshes a token', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated and refreshing the token should fail.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await expect(executor.updateToken(9999)).rejects.toThrow()
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated and refreshing the token should succeed.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.updateToken(9999)).toBe(true)
})

test('refreshes a token only if outside of expiry', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateRealm } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  await updateRealm({ accessTokenLifespan: 35 })
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  // The token should be refreshed if it is outside of expiry.
  expect(await executor.updateToken(30)).toBe(false)
  await executor.addTimeSkew(-5)
  expect(await executor.updateToken(30)).toBe(true)
})
