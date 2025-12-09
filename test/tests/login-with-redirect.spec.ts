import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.js'
import { REDIRECT_SERVICE_URL } from '../support/common.ts'
import { createTestBed, test } from '../support/testbed.ts'

/**
 * This test simulates a scenario where a user has configured the adapter to use a redirect URL
 * on a different domain than the application (e.g. a redirect service), which then redirects
 * back to the actual application. This redirect sits between the application and the auth server.
 */
test('logs in with a redirect service between the application and auth server', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })

  // Update the client to allow redirecting to the redirect service.
  await updateClient({
    redirectUris: [`${appUrl.origin}/*`, `${REDIRECT_SERVICE_URL.origin}/*`]
  })

  // Build the redirect URL that points to the redirect service instead of the application.
  const redirectUrl = new URL(REDIRECT_SERVICE_URL)
  redirectUrl.searchParams.set('origin', appUrl.origin)

  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    redirectUri: redirectUrl.toString()
  }

  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)

  await executor.login()
  await executor.submitLoginForm()

  // After login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)
})
