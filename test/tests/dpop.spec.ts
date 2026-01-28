import { expect } from '@playwright/test'
import type { KeycloakInitOptions } from '../../lib/keycloak.d.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in and out with DPoP enabled (auto mode)', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client..
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  // Track DPoP requests to the token endpoint
  let tokenRequestWithDPoP = false
  let tokenResponseType: string | null = null

  // Set up interceptor
  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()

    // Verify DPoP header is present
    if (headers['dpop']) {
      tokenRequestWithDPoP = true

      // Verify DPoP proof is a valid JWT (has 3 parts separated by dots)
      const dpopProof = headers['dpop']
      const parts = dpopProof.split('.')
      expect(parts.length).toBe(3) // JWT should have header.payload.signature
    }

    // Continue the request and capture the response
    const response = await route.fetch()
    const responseBody = await response.text()

    // Parse the token response to check token_type
    try {
      const tokenResponse = JSON.parse(responseBody)
      tokenResponseType = tokenResponse.token_type

      // Verify token_type is "DPoP" when DPoP is enabled
      expect(tokenResponse.token_type.toLowerCase()).toBe('dpop')
    } catch (error) {
      // If parsing fails, just continue
    }

    // Return the response to the browser
    await route.fulfill({
      response,
      body: responseBody
    })
  })

  // Initially, no user should be authenticated.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  // After triggering a login, the user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Verify that DPoP was actually used during token acquisition
  expect(tokenRequestWithDPoP).toBe(true)
  expect(tokenResponseType).not.toBeNull()
  expect(tokenResponseType!.toLowerCase()).toBe('dpop')

  await executor.logout()
  // After logging out, the user should no longer be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
})

test('logs in with DPoP in strict mode', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client..
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'strict' }
  }

  let tokenRequestWithDPoP = false
  let tokenResponseType: string | null = null

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()

    if (headers['dpop']) {
      tokenRequestWithDPoP = true
      const dpopProof = headers['dpop']
      const parts = dpopProof.split('.')
      expect(parts.length).toBe(3)
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    try {
      const tokenResponse = JSON.parse(responseBody)
      tokenResponseType = tokenResponse.token_type
      expect(tokenResponse.token_type.toLowerCase()).toBe('dpop')
    } catch (error) {
      // If parsing fails, just continue
    }

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Verify DPoP was used
  expect(tokenRequestWithDPoP).toBe(true)
  expect(tokenResponseType).not.toBeNull()
  expect(tokenResponseType!.toLowerCase()).toBe('dpop')
})

test('logs in with DPoP using ES256 algorithm', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client..
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto', alg: 'ES256' }
  }

  let dpopAlgorithm: string | null = null
  let tokenRequestWithDPoP = false

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()

    if (headers['dpop']) {
      tokenRequestWithDPoP = true
      const dpopProof = headers['dpop']
      const parts = dpopProof.split('.')
      expect(parts.length).toBe(3)

      // Decode the header to verify algorithm
      try {
        const header = JSON.parse(atob(parts[0]))
        dpopAlgorithm = header.alg
        expect(header.alg).toBe('ES256')
        expect(header.typ).toBe('dpop+jwt')
      } catch (error) {
        // If parsing fails, just continue
      }
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Verify ES256 algorithm was used
  expect(tokenRequestWithDPoP).toBe(true)
  expect(dpopAlgorithm).toBe('ES256')
})

test('logs in with DPoP using EdDSA algorithm', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client..
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto', alg: 'EdDSA' }
  }

  let dpopAlgorithm: string | null = null
  let tokenRequestWithDPoP = false

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()

    if (headers['dpop']) {
      tokenRequestWithDPoP = true
      const dpopProof = headers['dpop']
      const parts = dpopProof.split('.')
      expect(parts.length).toBe(3)

      // Decode the header to verify algorithm
      try {
        const header = JSON.parse(atob(parts[0]))
        dpopAlgorithm = header.alg
        expect(header.alg).toBe('EdDSA')
        expect(header.typ).toBe('dpop+jwt')
      } catch (error) {
        // If parsing fails, just continue
      }
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Verify EdDSA algorithm was used
  expect(tokenRequestWithDPoP).toBe(true)
  expect(dpopAlgorithm).toBe('EdDSA')
})

test('refreshes tokens with DPoP', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client..
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  let tokenRequestCount = 0
  let refreshRequestWithDPoP = false

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()
    const postData = request.postData()

    tokenRequestCount++

    // Check if this is a refresh token request
    const isRefreshRequest = postData?.includes('grant_type=refresh_token')

    if (isRefreshRequest && headers['dpop']) {
      refreshRequestWithDPoP = true
      const dpopProof = headers['dpop']
      const parts = dpopProof.split('.')
      expect(parts.length).toBe(3)
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Force a token refresh
  const refreshed = await executor.updateToken(-1)
  expect(refreshed).toBe(true)

  // Verify that DPoP was used for the refresh request
  expect(tokenRequestCount).toBeGreaterThanOrEqual(2) // Initial token + refresh
  expect(refreshRequestWithDPoP).toBe(true)
})

test('generates new DPoP key for each login session', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client..
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })
  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  let firstSessionJwk: string | null = null
  let secondSessionJwk: string | null = null

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()

    if (headers['dpop']) {
      const dpopProof = headers['dpop']
      const parts = dpopProof.split('.')

      try {
        // Decode the DPoP JWT header to extract the public key
        const header = JSON.parse(atob(parts[0]))
        const jwkString = JSON.stringify(header.jwk)

        // Capture the JWK from the first session
        if (firstSessionJwk === null) {
          firstSessionJwk = jwkString
        }
        // Capture the JWK from the second session (after logout/login)
        else if (secondSessionJwk === null) {
          secondSessionJwk = jwkString
        }
      } catch (error) {
        // If parsing fails, just continue
      }
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  // First session: login
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Verify first session has a DPoP key
  expect(firstSessionJwk).not.toBeNull()

  // Logout
  await executor.logout()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)

  // Second session: login again
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Verify second session has a different DPoP key
  expect(secondSessionJwk).not.toBeNull()
  expect(secondSessionJwk).not.toBe(firstSessionJwk)
})

test('logs in with OIDC provider configuration', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient, realm } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client..
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })

  // Use OIDC provider configuration instead of standard Keycloak config
  const oidcProviderUrl = `${authServerUrl.origin}/realms/${realm}`
  const oidcConfig = {
    clientId: executor.defaultConfig().clientId,
    oidcProvider: oidcProviderUrl
  }

  await executor.navigateToApp()
  await executor.instantiateAdapter(oidcConfig)

  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  let tokenRequestWithDPoP = false
  let tokenResponseType: string | null = null

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()

    if (headers['dpop']) {
      tokenRequestWithDPoP = true
      const dpopProof = headers['dpop']
      const parts = dpopProof.split('.')
      expect(parts.length).toBe(3) // JWT should have header.payload.signature
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    try {
      const tokenResponse = JSON.parse(responseBody)
      tokenResponseType = tokenResponse.token_type
      expect(tokenResponse.token_type.toLowerCase()).toBe('dpop')
    } catch (error) {
      // If parsing fails, just continue
    }

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  // Initialize and login
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Verify DPoP was used with OIDC provider config
  expect(tokenRequestWithDPoP).toBe(true)
  expect(tokenResponseType).not.toBeNull()
  expect(tokenResponseType!.toLowerCase()).toBe('dpop')

  await executor.logout()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
})

test('calls DPoP-protected resources with secureFetch', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client.
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })

  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  // Login with DPoP
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // First, try regular fetch with Bearer token (should fail because token is DPoP-bound)
  const regularFetchResponse = await page.evaluate(async () => {
    const keycloak = (globalThis as any).keycloak
    const userInfoUrl = keycloak.endpoints.userinfo()

    const resp = await fetch(userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${keycloak.token}`
      }
    })

    return {
      status: resp.status,
      ok: resp.ok
    }
  })

  // Verify regular fetch failed (DPoP-bound token requires DPoP proof)
  expect(regularFetchResponse.ok).toBe(false)
  expect(regularFetchResponse.status).toBe(401)

  // Now use secureFetch with Bearer token (should succeed because secureFetch adds DPoP proof)
  const secureFetchResponse = await page.evaluate(async () => {
    const keycloak = (globalThis as any).keycloak
    const userInfoUrl = keycloak.endpoints.userinfo()
    const resp = await keycloak.secureFetch(userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${keycloak.token}`
      }
    })
    const data = await resp.json()
    return {
      status: resp.status,
      data
    }
  })

  // Verify secureFetch succeeded
  expect(secureFetchResponse.status).toBe(200)
  expect(secureFetchResponse.data).toBeTruthy()
})

test('secureFetch calls open endpoints without DPoP when no Authorization header provided', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient, realm } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client.
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })

  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  let dpopHeaderSent = false

  // Intercept requests to the OIDC discovery endpoint (open endpoint, no auth required).
  const discoveryUrl = `${authServerUrl.origin}/realms/${realm}/.well-known/openid-configuration`
  await page.route('**/.well-known/openid-configuration', async (route) => {
    const headers = route.request().headers()

    // Check if DPoP header was sent.
    if (headers['dpop']) {
      dpopHeaderSent = true
    }

    // Let the request go through.
    await route.continue()
  })

  // Login with DPoP.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Use secureFetch to call an open endpoint without Authorization header.
  const response = await page.evaluate(async (url) => {
    const keycloak = (globalThis as any).keycloak
    const resp = await keycloak.secureFetch(url)
    const data = await resp.json()
    return {
      status: resp.status,
      hasIssuer: !!data.issuer
    }
  }, discoveryUrl)

  // Verify request succeeded.
  expect(response.status).toBe(200)
  expect(response.hasIssuer).toBe(true)

  // Verify NO DPoP header was sent (no Authorization header = no DPoP).
  expect(dpopHeaderSent).toBe(false)
})

test('secureFetch includes correct HTTP method in DPoP proof', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client.
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })

  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  const capturedProofs: Array<{ method: string, proof: string }> = []

  // Intercept requests to userinfo endpoint.
  await page.route('**/protocol/openid-connect/userinfo', async (route) => {
    const dpopHeader = route.request().headers()['dpop']
    const method = route.request().method()

    if (dpopHeader) {
      capturedProofs.push({ method, proof: dpopHeader })
    }

    // For non-GET methods, return a mock success response.
    if (method !== 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ sub: 'test-user' })
      })
    } else {
      // Let GET requests go through to Keycloak.
      await route.continue()
    }
  })

  // Login with DPoP.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Test GET, POST, PUT, DELETE methods.
  const methods = ['GET', 'POST', 'PUT', 'DELETE'] as const

  for (const method of methods) {
    await page.evaluate(async (testMethod) => {
      const keycloak = (globalThis as any).keycloak
      const userInfoUrl = keycloak.endpoints.userinfo()

      await keycloak.secureFetch(userInfoUrl, {
        method: testMethod,
        headers: {
          'Authorization': `Bearer ${keycloak.token}`,
          'Content-Type': 'application/json'
        },
        body: testMethod !== 'GET' ? JSON.stringify({}) : undefined
      })
    }, method)
  }

  // Verify we captured proofs for all methods.
  expect(capturedProofs.length).toBe(4)

  // Verify each proof has the correct htm (HTTP method) claim.
  for (let i = 0; i < methods.length; i++) {
    const { method, proof } = capturedProofs[i]
    const parts = proof.split('.')
    expect(parts.length).toBe(3)

    const payload = JSON.parse(atob(parts[1]))
    expect(payload.htm).toBe(method)
    expect(payload.htu).toContain('userinfo')
  }
})

test('handles concurrent secureFetch calls correctly', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  // Enable DPoP on the client.
  await updateClient({ attributes: { 'dpop.bound.access.tokens': 'true' } })

  const initOptions: KeycloakInitOptions = {
    ...executor.defaultInitOptions(),
    useDPoP: { mode: 'auto' }
  }

  const capturedJtis: Set<string> = new Set()
  const capturedProofs: string[] = []

  // Intercept requests to userinfo endpoint.
  await page.route('**/protocol/openid-connect/userinfo', async (route) => {
    const dpopHeader = route.request().headers()['dpop']

    if (dpopHeader) {
      capturedProofs.push(dpopHeader)

      const parts = dpopHeader.split('.')
      const payload = JSON.parse(atob(parts[1]))
      capturedJtis.add(payload.jti)
    }

    // Let the request go through.
    await route.continue()
  })

  // Login with DPoP.
  await executor.navigateToApp()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  // Make 5 concurrent secureFetch calls.
  const responses = await page.evaluate(async () => {
    const keycloak = (globalThis as any).keycloak
    const userInfoUrl = keycloak.endpoints.userinfo()

    const promises = Array(5).fill(null).map(() =>
      keycloak.secureFetch(userInfoUrl, {
        headers: {
          'Authorization': `Bearer ${keycloak.token}`
        }
      }).then((resp: Response) => resp.status)
    )

    return await Promise.all(promises)
  })

  // Verify all requests succeeded.
  expect(responses.length).toBe(5)
  responses.forEach(status => {
    expect(status).toBe(200)
  })

  // Verify we captured 5 DPoP proofs.
  expect(capturedProofs.length).toBe(5)

  // Verify each proof has a unique jti (replay protection).
  expect(capturedJtis.size).toBe(5)

  // Verify all proofs use the same JWK (same session).
  const jwks = capturedProofs.map(proof => {
    const parts = proof.split('.')
    const header = JSON.parse(atob(parts[0]))
    return JSON.stringify(header.jwk)
  })

  const uniqueJwks = new Set(jwks)
  expect(uniqueJwks.size).toBe(1)
})