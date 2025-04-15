import { expect } from '@playwright/test'
import { AUTHORIZED_USERNAME } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('loads the user profile', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated and loading the user profile should fail.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await expect(executor.loadUserProfile()).rejects.toThrow()
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated and loading the user profile should succeed.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.loadUserProfile()).toMatchObject({ username: AUTHORIZED_USERNAME })
})
