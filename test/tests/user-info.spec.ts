import { expect } from '@playwright/test'
import { AUTHORIZED_USERNAME } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('loads the user info', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated and loading the user info should fail.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await expect(executor.loadUserInfo()).rejects.toThrow('Unable to build authorization header, token is not set, make sure the user is authenticated.')
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated and loading the user info should succeed.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.userInfo()).toBeUndefined()
  expect(await executor.loadUserInfo()).toMatchObject({ email: AUTHORIZED_USERNAME })
  expect(await executor.userInfo()).toMatchObject({ email: AUTHORIZED_USERNAME })
})
