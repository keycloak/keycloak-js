import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.d.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in with a query response mode when URLSearchParams.size is unavailable', async ({ page, appUrl, authServerUrl }) => {
  // Simulate browsers without URLSearchParams.size support, such as Safari 16,
  // where the property is undefined and the query callback would be skipped
  // entirely, causing an infinite redirect loop between the application and
  // the auth server.
  await page.addInitScript(() => {
    delete (URLSearchParams.prototype as { size?: number }).size
  })

  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    responseMode: 'query'
  }

  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)

  // After logging in, the query callback should still be parsed, and the user
  // should be authenticated.
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)
})
