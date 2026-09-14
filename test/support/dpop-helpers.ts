import { expect, type Page } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.d.ts'
import type { TestBed } from './testbed.ts'
import type { TestExecutor } from './test-executor.ts'

export async function enableDPoPBoundTokens (updateClient: TestBed['updateClient']): Promise<void> {
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })
}

export function dpopInitOptions (
  executor: TestExecutor,
  useDPoP: NonNullable<KeycloakInitOptions['useDPoP']>
): KeycloakInitOptions {
  return {
    ...executor.defaultInitOptions(),
    useDPoP
  }
}

export interface TokenEndpointTracker {
  tokenRequestWithDPoP: boolean
  tokenResponseType: string | null
}

export interface InterceptTokenEndpointOptions {
  assertTokenType?: boolean
  onDPoPProof?: (proof: string) => void
}

export async function interceptTokenEndpoint (
  page: Page,
  options: InterceptTokenEndpointOptions = {}
): Promise<TokenEndpointTracker> {
  const { assertTokenType = true, onDPoPProof } = options
  const tracker: TokenEndpointTracker = {
    tokenRequestWithDPoP: false,
    tokenResponseType: null
  }

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const headers = route.request().headers()

    if (headers.dpop !== undefined) {
      tracker.tokenRequestWithDPoP = true
      const dpopProof = headers.dpop
      const parts = dpopProof.split('.')
      expect(parts.length).toBe(3)
      onDPoPProof?.(dpopProof)
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    if (assertTokenType) {
      try {
        const tokenResponse = JSON.parse(responseBody)
        tracker.tokenResponseType = tokenResponse.token_type
        expect(tokenResponse.token_type.toLowerCase()).toBe('dpop')
      } catch {
        // If parsing fails, continue without asserting token type.
      }
    }

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  return tracker
}

export async function loginWithDPoP (
  executor: TestExecutor,
  initOptions: KeycloakInitOptions
): Promise<void> {
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)
}

export function decodeDPoPProofHeader (proof: string): Record<string, unknown> {
  const parts = proof.split('.')
  return JSON.parse(atob(parts[0]))
}
