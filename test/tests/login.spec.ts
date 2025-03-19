import { expect, test } from '@playwright/test'
import { createTestResources } from '../support/helpers.ts'
import { TestExecutor } from '../support/test-executor.ts'

test('logs in and out', async ({ page }) => {
  const realm = await createTestResources()
  const executor = new TestExecutor(page, realm)
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter()).toBe(false)
  // After triggering a login, the user should be authenticated.
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter()).toBe(true)
  // After logging out, the user should no longer be authenticated.
  await executor.logout()
  expect(await executor.initializeAdapter()).toBe(false)
})
