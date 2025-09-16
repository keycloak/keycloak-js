import { expect } from '@playwright/test'
import { createTestBed, test } from '../support/testbed.ts'
import type { KeycloakFlow, KeycloakResponseMode } from '../../lib/keycloak.js';

test('throws when initializing multiple times', async ({ page, appUrl, authServerUrl }) => {
  const { executor } = await createTestBed(page, { appUrl, authServerUrl })
  await executor.initializeAdapter()
  await expect(executor.initializeAdapter()).rejects.toThrow("A 'Keycloak' instance can only be initialized once.")
});

const standardParams = ['code', 'state', 'session_state', 'kc_action_status', 'kc_action', 'iss'];
const implicitParams = ['access_token', 'token_type', 'id_token', 'state', 'session_state', 'expires_in', 'kc_action_status', 'kc_action', 'iss'];
const hybridParams = ['access_token', 'token_type', 'id_token', 'code', 'state', 'session_state', 'expires_in', 'kc_action_status', 'kc_action', 'iss'];
const errorParams = ['error', 'error_description', 'error_uri'];

[
  {
    flow: 'standard',
    responseMode: 'fragment',
    params: [...standardParams, ...errorParams]
  },
  {
    flow: 'standard',
    responseMode: 'query',
    params: [...standardParams, ...errorParams]
  },
  {
    flow: 'implicit',
    responseMode: 'fragment',
    params: [...implicitParams, ...errorParams]
  },
  {
    flow: 'hybrid',
    responseMode: 'fragment',
    params: [...hybridParams, ...errorParams]
  },
].forEach(({ flow, responseMode, params }) => {
  const addRandomParams = (url: Readonly<URL>, params: string[], mode: string) => {
    const newUrl = new URL(url);
    for (const param of params) {
      if (mode === 'query') {
        newUrl.searchParams.set(param, `test-${param}`);
      } else {
        newUrl.hash = `${newUrl.hash ? newUrl.hash + '&' : ''}${param}=test-${param}`;
      }
    }
    return newUrl;
  };

  test(`[${responseMode} / ${flow}] should remove authorization response parameters from redirect URL`, async ({ page, appUrl, authServerUrl }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });
    const redirect = addRandomParams(appUrl, params, responseMode);

    await page.goto(redirect.toString());
    await executor.initializeAdapter({
      responseMode: responseMode as KeycloakResponseMode,
      flow: flow as KeycloakFlow,
      redirectUri: appUrl.toString()
    });
    // Wait for the adapter to process the redirect and clean up the URL
    await page.evaluate(() => {
      return new Promise((resolve) => setTimeout(resolve, 0));
    });

    // Check that the URL has been cleaned up
    const currentUrl = page.url();
    const url = new URL(currentUrl);
    for (const param of params) {
      if (responseMode === 'query') {
        expect(url.searchParams.has(param)).toBe(false);
      } else {
        expect(url.hash).not.toContain(`${param}=`);
      }
    }
  });

  test(`[${responseMode} / ${flow}] should preserve parameters from the URL on non-redirect pages`, async ({ page, appUrl, authServerUrl }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });

    // Visit the App URL before initialization
    const newAppUrl = addRandomParams(appUrl, params, responseMode);
    await page.goto(newAppUrl.toString());

    const redirectUri = new URL('callback', newAppUrl);
    await executor.initializeAdapter({
      responseMode: responseMode as KeycloakResponseMode,
      flow: flow as KeycloakFlow,
      redirectUri: redirectUri.toString()
    });
    // Wait for the adapter to process the redirect and possibly clean up the URL
    await page.evaluate(() => {
      return new Promise((resolve) => setTimeout(resolve, 0));
    });

    // Check that the URL has NOT been cleaned up
    const currentUrl = page.url();
    const url = new URL(currentUrl);
    for (const param of params) {
      if (responseMode === 'query') {
        expect(url.searchParams.has(param)).toBe(true);
      } else {
        expect(url.hash).toContain(`${param}=`);
      }
    }
  });
});