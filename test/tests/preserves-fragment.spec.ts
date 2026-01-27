import { expect } from '@playwright/test'
import { createTestBed, test } from '../support/testbed.ts'

test('preserves basic URL fragment', async ({ page, appUrl, authServerUrl }) => {
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
})

test('preserves fragment with conflicting (known oauth) params', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const fragment = '#state=anotherValue'
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  await page.goto(appUrlWithFragment.toString())

  // Initialize the adapter and perform login.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // After login and adapter initialization, the URL fragment should be preserved.
  await executor.initializeAdapter(initOptions)
  expect(new URL(await page.url()).hash).toBe(fragment)
})

test('preserves path-style URL fragment', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const fragment = '#/admin/users'
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  await page.goto(appUrlWithFragment.toString())

  // Initialize the adapter and perform login.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // After login and adapter initialization, the URL fragment should be preserved.
  await executor.initializeAdapter(initOptions)
  expect(new URL(await page.url()).hash).toBe(fragment)
})

test('preserves path-style fragment with query params', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const fragment = '#/admin/users?tab=details&sort=asc'
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  await page.goto(appUrlWithFragment.toString())

  // Initialize the adapter and perform login.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // After login and adapter initialization, the URL fragment should be preserved.
  await executor.initializeAdapter(initOptions)
  expect(new URL(await page.url()).hash).toBe(fragment)
})

test('preserves fragment with leading question mark', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const fragment = '#?tab=details'
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  await page.goto(appUrlWithFragment.toString())

  // Initialize the adapter and perform login.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // After login and adapter initialization, the URL fragment should be preserved.
  await executor.initializeAdapter(initOptions)
  expect(new URL(await page.url()).hash).toBe(fragment)
})

test('preserves fragment with multiple ampersands', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  const fragment = '#&&foo=bar&&baz=qux&=bax&fuz='
  const appUrlWithFragment = new URL(appUrl)

  appUrlWithFragment.hash = fragment

  await page.goto(appUrlWithFragment.toString())

  // Initialize the adapter and perform login.
  await executor.initializeAdapter(initOptions)
  await executor.login()
  await executor.submitLoginForm()

  // After login and adapter initialization, the URL fragment should be preserved.
  await executor.initializeAdapter(initOptions)
  expect(new URL(await page.url()).hash).toBe(fragment)
})
