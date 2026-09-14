import { expect } from '@playwright/test'
import {
  decodeDPoPProofHeader,
  dpopInitOptions,
  enableDPoPBoundTokens,
  interceptTokenEndpoint,
  loginWithDPoP
} from '../support/dpop-helpers.ts'
import { createTestBed, test } from '../support/testbed.ts'

test('logs in and out with DPoP enabled (auto mode)', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })
  const tracker = await interceptTokenEndpoint(page)

  await loginWithDPoP(executor, initOptions)

  expect(tracker.tokenRequestWithDPoP).toBe(true)
  expect(tracker.tokenResponseType).not.toBeNull()
  expect(String(tracker.tokenResponseType).toLowerCase()).toBe('dpop')

  await executor.logout()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
})

test('logs in with DPoP in strict mode', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'strict' })
  const tracker = await interceptTokenEndpoint(page)

  await loginWithDPoP(executor, initOptions)

  expect(tracker.tokenRequestWithDPoP).toBe(true)
  expect(tracker.tokenResponseType).not.toBeNull()
  expect(String(tracker.tokenResponseType).toLowerCase()).toBe('dpop')
})

for (const alg of ['ES256', 'EdDSA'] as const) {
  test(`logs in with DPoP using ${alg} algorithm`, async ({ page, appUrl, authServerUrl }) => {
    const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
    await enableDPoPBoundTokens(updateClient)
    const initOptions = dpopInitOptions(executor, { mode: 'auto', alg })
    let dpopAlgorithm: string | null = null

    await interceptTokenEndpoint(page, {
      onDPoPProof: (proof) => {
        const header = decodeDPoPProofHeader(proof)
        dpopAlgorithm = header.alg as string
        expect(header.alg).toBe(alg)
        expect(header.typ).toBe('dpop+jwt')
      }
    })

    await loginWithDPoP(executor, initOptions)

    expect(dpopAlgorithm).toBe(alg)
  })
}

test('refreshes tokens with DPoP', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })

  let tokenRequestCount = 0
  let refreshRequestWithDPoP = false

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const request = route.request()
    const headers = request.headers()
    const postData = request.postData()

    tokenRequestCount++

    const isRefreshRequest = postData?.includes('grant_type=refresh_token') ?? false

    if (isRefreshRequest && headers.dpop !== undefined) {
      refreshRequestWithDPoP = true
      const parts = headers.dpop.split('.')
      expect(parts.length).toBe(3)
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  await loginWithDPoP(executor, initOptions)

  const refreshed = await executor.updateToken(-1)
  expect(refreshed).toBe(true)

  expect(tokenRequestCount).toBeGreaterThanOrEqual(2)
  expect(refreshRequestWithDPoP).toBe(true)
})

test('generates new DPoP key for each login session', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })

  let firstSessionJwk: string | null = null
  let secondSessionJwk: string | null = null

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const headers = route.request().headers()

    if (headers.dpop !== undefined) {
      try {
        const header = decodeDPoPProofHeader(headers.dpop)
        const jwkString = JSON.stringify(header.jwk)

        if (firstSessionJwk === null) {
          firstSessionJwk = jwkString
        } else if (secondSessionJwk === null) {
          secondSessionJwk = jwkString
        }
      } catch {
        // If parsing fails, continue without capturing the JWK.
      }
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  await loginWithDPoP(executor, initOptions)
  expect(firstSessionJwk).not.toBeNull()

  await executor.logout()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)

  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  expect(secondSessionJwk).not.toBeNull()
  expect(secondSessionJwk).not.toBe(firstSessionJwk)
})

test('generates new DPoP key when clearToken is called', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })

  let firstSessionJwk: string | null = null
  let secondSessionJwk: string | null = null

  await page.route('**/protocol/openid-connect/token', async (route) => {
    const headers = route.request().headers()

    if (headers.dpop !== undefined) {
      try {
        const header = decodeDPoPProofHeader(headers.dpop)
        const jwkString = JSON.stringify(header.jwk)

        if (firstSessionJwk === null) {
          firstSessionJwk = jwkString
        } else if (secondSessionJwk === null) {
          secondSessionJwk = jwkString
        }
      } catch {
        // If parsing fails, continue without capturing the JWK.
      }
    }

    const response = await route.fetch()
    const responseBody = await response.text()

    await route.fulfill({
      response,
      body: responseBody
    })
  })

  await loginWithDPoP(executor, initOptions)
  expect(firstSessionJwk).not.toBeNull()

  await page.evaluate(async () => {
    const keycloak = (globalThis as any).keycloak
    await keycloak.clearToken()
  })

  expect(await executor.isAuthenticated()).toBe(false)

  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  expect(secondSessionJwk).not.toBeNull()
  expect(secondSessionJwk).not.toBe(firstSessionJwk)
})

test('logs in with OIDC provider configuration', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)

  const oidcProviderUrl = `${authServerUrl.origin}/realms/${realm}`
  const oidcConfig = {
    clientId: executor.defaultConfig().clientId,
    oidcProvider: oidcProviderUrl
  }

  await executor.navigateToApp()
  await executor.instantiateAdapter(oidcConfig)

  const initOptions = dpopInitOptions(executor, { mode: 'auto' })
  const tracker = await interceptTokenEndpoint(page)

  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
  await executor.login()
  await executor.submitLoginForm()
  expect(await executor.initializeAdapter(initOptions)).toBe(true)
  expect(await executor.isAuthenticated()).toBe(true)

  expect(tracker.tokenRequestWithDPoP).toBe(true)
  expect(tracker.tokenResponseType).not.toBeNull()
  expect(String(tracker.tokenResponseType).toLowerCase()).toBe('dpop')

  await executor.logout()
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  expect(await executor.isAuthenticated()).toBe(false)
})

test('calls DPoP-protected resources with secureFetch', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })

  await loginWithDPoP(executor, initOptions)

  const regularFetchResponse = await page.evaluate(async () => {
    const keycloak = (globalThis as any).keycloak
    const userInfoUrl = keycloak.endpoints.userinfo()

    const resp = await fetch(userInfoUrl, {
      headers: {
        Authorization: `Bearer ${String(keycloak.token)}`
      }
    })

    return {
      status: resp.status,
      ok: resp.ok
    }
  })

  expect(regularFetchResponse.ok).toBe(false)
  expect(regularFetchResponse.status).toBe(401)

  const secureFetchResponse = await page.evaluate(async () => {
    const keycloak = (globalThis as any).keycloak
    const userInfoUrl = keycloak.endpoints.userinfo()
    const resp = await keycloak.secureFetch(userInfoUrl, {
      headers: {
        Authorization: `Bearer ${String(keycloak.token)}`
      }
    })
    const data = await resp.json()
    return {
      status: resp.status,
      data
    }
  })

  expect(secureFetchResponse.status).toBe(200)
  expect(secureFetchResponse.data).toBeTruthy()
})

test('secureFetch calls open endpoints without DPoP when no Authorization header provided', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient, realm } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })

  let dpopHeaderSent = false
  const discoveryUrl = `${authServerUrl.origin}/realms/${realm}/.well-known/openid-configuration`

  await page.route('**/.well-known/openid-configuration', async (route) => {
    if (route.request().headers().dpop !== undefined) {
      dpopHeaderSent = true
    }
    await route.continue()
  })

  await loginWithDPoP(executor, initOptions)

  const response = await page.evaluate(async (url) => {
    const keycloak = (globalThis as any).keycloak
    const resp = await keycloak.secureFetch(url)
    const data = await resp.json()
    return {
      status: resp.status,
      hasIssuer: data.issuer !== undefined
    }
  }, discoveryUrl)

  expect(response.status).toBe(200)
  expect(response.hasIssuer).toBe(true)
  expect(dpopHeaderSent).toBe(false)
})

test('secureFetch includes correct HTTP method in DPoP proof', async ({ page, appUrl, authServerUrl }) => {
  const { executor, updateClient } = await createTestBed(page, { appUrl, authServerUrl })
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })

  const capturedProofs: Array<{ method: string, proof: string }> = []

  await page.route('**/protocol/openid-connect/userinfo', async (route) => {
    const dpopHeader = route.request().headers().dpop
    const method = route.request().method()

    if (dpopHeader !== undefined) {
      capturedProofs.push({ method, proof: dpopHeader })
    }

    if (method !== 'GET') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ sub: 'test-user' })
      })
    } else {
      await route.continue()
    }
  })

  await loginWithDPoP(executor, initOptions)

  const methods = ['GET', 'POST', 'PUT', 'DELETE'] as const

  for (const method of methods) {
    await page.evaluate(async (testMethod) => {
      const keycloak = (globalThis as any).keycloak
      const userInfoUrl = keycloak.endpoints.userinfo()

      await keycloak.secureFetch(userInfoUrl, {
        method: testMethod,
        headers: {
          Authorization: `Bearer ${String(keycloak.token)}`,
          'Content-Type': 'application/json'
        },
        body: testMethod !== 'GET' ? JSON.stringify({}) : undefined
      })
    }, method)
  }

  expect(capturedProofs.length).toBe(4)

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
  await enableDPoPBoundTokens(updateClient)
  const initOptions = dpopInitOptions(executor, { mode: 'auto' })

  const capturedJtis = new Set<string>()
  const capturedProofs: string[] = []

  await page.route('**/protocol/openid-connect/userinfo', async (route) => {
    const dpopHeader = route.request().headers().dpop

    if (dpopHeader !== undefined) {
      capturedProofs.push(dpopHeader)

      const parts = dpopHeader.split('.')
      const payload = JSON.parse(atob(parts[1]))
      capturedJtis.add(payload.jti)
    }

    await route.continue()
  })

  await loginWithDPoP(executor, initOptions)

  const responses = await page.evaluate(async () => {
    const keycloak = (globalThis as any).keycloak
    const userInfoUrl = keycloak.endpoints.userinfo()

    const promises = Array(5).fill(null).map(() =>
      keycloak.secureFetch(userInfoUrl, {
        headers: {
          Authorization: `Bearer ${String(keycloak.token)}`
        }
      }).then((resp: Response) => resp.status)
    )

    return await Promise.all(promises)
  })

  expect(responses.length).toBe(5)
  responses.forEach(status => {
    expect(status).toBe(200)
  })

  expect(capturedProofs.length).toBe(5)
  expect(capturedJtis.size).toBe(5)

  const jwks = capturedProofs.map(proof => {
    const header = decodeDPoPProofHeader(proof)
    return JSON.stringify(header.jwk)
  })

  expect(new Set(jwks).size).toBe(1)
})
