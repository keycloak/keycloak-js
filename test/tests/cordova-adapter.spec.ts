import { expect } from "@playwright/test";
import { createTestBed, test } from "../support/testbed.ts";
import { setupCordovaMock } from "../support/cordova.ts";

test.describe("Cordova adapter", () => {
  test("initializes with cordova adapter", async ({
    page,
    appUrl,
    authServerUrl,
  }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });
    const initOptions = executor.cordovaInitOptions();
    expect(await executor.initializeAdapter(initOptions)).toBe(false);
    expect(await executor.isAuthenticated()).toBe(false);
  });

  test("logs in with cordova adapter and InAppBrowser", async ({
    page,
    appUrl,
    authServerUrl,
  }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });
    const initOptions = executor.cordovaInitOptions();
    expect(await executor.initializeAdapter(initOptions)).toBe(false);
    await setupCordovaMock(page, appUrl, authServerUrl);

    const loginPromise = executor.login();
    await expect(loginPromise).resolves.toBeUndefined();
    expect(await executor.isAuthenticated()).toBe(true);
    expect(page.context().pages().length).toBe(1);
  });

  test("should pass location=no option by default to InAppBrowser", async ({
    page,
    appUrl,
    authServerUrl,
  }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });
    const initOptions = executor.cordovaInitOptions();
    expect(await executor.initializeAdapter(initOptions)).toBe(false);
    const refHandle = await setupCordovaMock(page, appUrl, authServerUrl);

    const loginPromise = executor.login();
    await expect(loginPromise).resolves.toBeUndefined();
    const options = await refHandle.evaluate((ref) =>
      ref._getCapturedOptions()
    );
    expect(options).toBe("location=no");
  });

  test("handles cordova adapter logout", async ({
    page,
    appUrl,
    authServerUrl,
  }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });
    const initOptions = executor.cordovaInitOptions();
    expect(await executor.initializeAdapter(initOptions)).toBe(false);
    await setupCordovaMock(page, appUrl, authServerUrl);

    const loginPromise = executor.login();
    await expect(loginPromise).resolves.toBeUndefined();
    expect(await executor.isAuthenticated()).toBe(true);

    await executor.logout(undefined, true);
    expect(await executor.isAuthenticated()).toBe(false);
    expect(page.context().pages().length).toBe(1);
  });

  // needs fix for https://github.com/keycloak/keycloak-js/issues/208 - we could also drop it
  test.skip("allow loaderror on InAppBrowser before finishing login", async ({
    page,
    appUrl,
    authServerUrl,
  }) => {
    const { executor } = await createTestBed(page, { appUrl, authServerUrl });
    const initOptions = executor.cordovaInitOptions();
    expect(await executor.initializeAdapter(initOptions)).toBe(false);
    const refHandle = await setupCordovaMock(page, appUrl, authServerUrl, {
      onInAppBrowserRedirect: async (refHandle) => {
        await refHandle.evaluate((ref) => {
          ref._triggerEvent("loaderror", {
            type: "loaderror",
            url: "some other url",
            code: -2,
            message: "Simulated loaderror",
          });
        });
      },
    });

    const loginPromise = executor.login();
    await expect(loginPromise).resolves.toBeUndefined();
    expect(await executor.isAuthenticated()).toBe(true);
  });
});
