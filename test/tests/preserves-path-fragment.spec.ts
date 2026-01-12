import { expect } from '@playwright/test'
import { createTestBed, test } from '../support/testbed.ts'

test('preserves path-style URL fragment after login', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Test with a path-style fragment (like hash-based routing)
  const fragment = '#/admin/maintenance/scripts'
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  // Navigate to the application URL with a path fragment.
  await page.goto(appUrlWithFragment.toString())

  // Initialize the adapter and perform login.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // Re-initialize after OAuth redirect to process the callback parameters.
  await executor.initializeAdapter(initOptions)
  const finalHash = new URL(await page.url()).hash

  expect(finalHash).toBe(fragment)
  // Ensure the fragment is not URL-encoded
  expect(finalHash).not.toContain('%2F')
  expect(finalHash).not.toContain('%3D')
})

test('preserves path-style fragment with query params after login', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Test with a path-style fragment that includes query parameters
  const fragment = '#/admin/users?tab=details'
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  await page.goto(appUrlWithFragment.toString())
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // Re-initialize after OAuth redirect to process the callback parameters.
  await executor.initializeAdapter(initOptions)
  const finalHash = new URL(await page.url()).hash

  expect(finalHash).toBe(fragment)
  expect(finalHash).not.toContain('%2F')
})
