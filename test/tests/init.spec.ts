import { expect } from '@playwright/test'
import { createTestBed, test } from '../support/testbed.ts'

test('throws when initializing multiple times', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter()
  await expect(executor.initializeAdapter()).rejects.toThrow("A 'Keycloak' instance can only be initialized once.")
})
