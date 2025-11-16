import type { BrowserContext, JSHandle, Page } from "@playwright/test";
import { createTestBed } from "./testbed.ts";

export const CORDOVA_REDIRECT_URL = new URL("http://localhost");

export async function setupCordovaMock(
  page: Page,
  appUrl: URL,
  authServerUrl: URL
) {
  const browserContext = page.context();
  const refHandle = await getInAppBrowserRefMock(page);
  setupEventTriggerOnNewPageForInAppBrowserRef(
    browserContext,
    page,
    refHandle,
    appUrl,
    authServerUrl
  );
  await injectCordovaInAppBrowserMock(page, refHandle);
  return refHandle;
}

export async function getInAppBrowserRefMock(page: Page) {
  return page.evaluateHandle(() => {
    const eventListeners: { [key: string]: Function[] } = {};
    let options: string | undefined;
    return {
      addEventListener: (event: string, callback: Function) => {
        if (!eventListeners[event]) eventListeners[event] = [];
        eventListeners[event].push(callback);
      },
      close: async () => {
        await (window as any).closeInAppBrowserPage();
        eventListeners["exit"]?.forEach((cb) => cb({}));
      },
      _triggerEvent: (event: string, data: any) => {
        eventListeners[event]?.forEach((cb) => cb(data));
      },
      _captureOptions: (opts: any) => {
        options = opts;
      },
      _getCapturedOptions: () => {
        return options;
      },
      _reset: () => {
        options = undefined;
        for (const key in eventListeners) {
          delete eventListeners[key];
        }
      },
    };
  });
}

export async function injectCordovaInAppBrowserMock(
  page: Page,
  refHandle: JSHandle<{
    addEventListener: (event: string, callback: Function) => void;
    close: () => void;
    _triggerEvent: (event: string, data: any) => void;
    _captureOptions: (opts: any) => void;
    _reset: () => void;
  }>
) {
  await page.evaluate((ref) => {
    (window as any).cordova = {
      InAppBrowser: {
        open: (url: string, target: string, options: string) => {
          ref._reset();
          window.open(url, target, options);
          ref._captureOptions(options);
          return ref;
        },
      },
    };
  }, refHandle);
}

export async function setupEventTriggerOnNewPageForInAppBrowserRef(
  browserContext: BrowserContext,
  page: Page,
  refHandle: JSHandle<any>,
  appUrl: URL,
  authServerUrl: URL
) {
  let currentlyOpenPage: Page | null = null;
  browserContext.on("page", async (newPage) => {
    currentlyOpenPage = newPage;
    await newPage.waitForLoadState();
    const { executor: newExecutor } = await createTestBed(newPage, {
      appUrl,
      authServerUrl,
    });
    const loginLocator = await newPage.getByRole("textbox", {
      name: "Username or email",
    });
    if (await loginLocator.isVisible()) {
      await newExecutor.submitLoginForm();
    }
    const pageUrl = newPage.url();

    await refHandle.evaluate(
      (ref, { pageUrl }) => {
        ref._triggerEvent("loadstart", { url: pageUrl });
      },
      { pageUrl }
    );
  });
  await page.exposeFunction("closeInAppBrowserPage", async () => {
    if (currentlyOpenPage && !currentlyOpenPage.isClosed()) {
      await currentlyOpenPage.close();
    }
  });
}
