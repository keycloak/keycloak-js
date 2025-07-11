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
  const addRandomParams = (url: URL, params: string[], mode: string) => {
    for (const param of params) {
      if (mode === 'query') {
        url.searchParams.set(param, `test-${param}`);
      } else {
        url.hash = `${url.hash ? url.hash + '&' : ''}${param}=test-${param}`;
      }
    }
  };

  test(`[${responseMode} / ${flow}] should remove authorization response parameters from redirect URL`, async ({ page, appUrl, authServerUrl }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });
    const redirectUri = new URL('callback', appUrl);
    await executor.initializeAdapter({
      responseMode: responseMode as KeycloakResponseMode,
      flow: flow as KeycloakFlow,
      redirectUri: redirectUri.toString()
    });

    // Simulate a redirect with authorization response parameters
    const redirect = new URL(redirectUri);
    addRandomParams(redirect, params, responseMode);

    await page.goto(redirectUri.toString());
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
    addRandomParams(appUrl, params, responseMode);
    await page.goto(appUrl.toString());

    const redirectUri = new URL('callback', appUrl);
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