import { expect } from '@playwright/test'
import { createTestBed, test } from '../support/testbed.ts'
import type { Acr } from '../../lib/keycloak.js'

interface ClaimsParam {
  id_token: {
    acr: Acr
  }
}

test('adds the acr values as claims to the login url', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  const loginUrl = await executor.createLoginUrl({
    acr: {
      values: ['foo', 'bar'],
      essential: false
    }
  })
  // The login URL should contain the claims parameter with the acr values.
  const claimsParam: ClaimsParam = JSON.parse(new URL(loginUrl).searchParams.get('claims') as string)
  expect(claimsParam).toMatchObject({
    id_token: {
      acr: {
        values: ['foo', 'bar'],
        essential: false
      }
    }
  })
})

test('adds the acr values directly to the login url', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  const initOptions = executor.defaultInitOptions()
  // Initially, no user should be authenticated.
  expect(await executor.initializeAdapter(initOptions)).toBe(false)
  // The login URL should contain the acr_values parameter with the acr values.
  const loginUrl = await executor.createLoginUrl({
    acrValues: '2fa'
  })
  expect(new URL(loginUrl).searchParams.get('acr_values')).toBe('2fa')
})
