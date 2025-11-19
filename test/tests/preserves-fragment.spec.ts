import { expect } from '@playwright/test'
import { createTestBed, test } from '../support/testbed.ts'

test('preserves URL fragment after login and logout', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const fragment = '#section=preserved'
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  // Navigate to the application URL with a fragment.
  await page.goto(appUrlWithFragment.toString())

  // Initialize the adapter and perform login.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // After login and adapter initialization, the URL fragment should be preserved.
  await executor.initializeAdapter(initOptions)
  expect(new URL(await page.url()).hash).toBe(fragment)

  // After logout, the URL fragment should still be preserved.
  await executor.logout()
  await executor.initializeAdapter(initOptions)
  expect(new URL(await page.url()).hash).toBe(fragment)
})
