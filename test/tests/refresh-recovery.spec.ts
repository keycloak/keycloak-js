import { expect, test } from '@playwright/test'
import type Keycloak from '../../lib/keycloak.js'

test('recovers from a refresh attempted before initialization', async ({ page, baseURL }) => {
  const appUrl = new URL(baseURL!)
  const tokenUrl = new URL('/realms/test/protocol/openid-connect/token', appUrl)
  const payload = Buffer.from(JSON.stringify({ sub: 'test-user', iat: Math.floor(Date.now() / 1000) })).toString('base64url')
  let refreshRequests = 0
  await page.route(tokenUrl.toString(), async route => {
    refreshRequests++
    await route.fulfill({ json: { access_token: `e30.${payload}.`, refresh_token: `e30.${payload}.`, token_type: 'Bearer' } })
  })

  await page.goto(appUrl.toString())
  await page.waitForFunction(() => 'Keycloak' in globalThis)
  await page.evaluate((url) => {
    const globals = globalThis as typeof globalThis & { Keycloak: typeof Keycloak, keycloak: Keycloak }
    globals.keycloak = new globals.Keycloak({ url, realm: 'test', clientId: 'client' })
    globals.keycloak.refreshToken = 'stored-refresh-token'
  }, appUrl.origin)

  await expect(page.evaluate(() => (globalThis as typeof globalThis & { keycloak: Keycloak }).keycloak.updateToken(-1))).rejects.toThrow()

  const results = await page.evaluate(async () => {
    const { keycloak } = globalThis as typeof globalThis & { keycloak: Keycloak }
    await keycloak.init({ checkLoginIframe: false })
    keycloak.refreshToken = 'stored-refresh-token'
    return await Promise.all([keycloak.updateToken(-1), keycloak.updateToken(-1)])
  })

  expect(results).toEqual([true, true])
  expect(refreshRequests).toBe(1)
})
