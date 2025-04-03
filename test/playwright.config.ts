import { defineConfig, devices } from '@playwright/test'
import { APP_URL, APP_URL_CROSS_ORIGIN, AUTH_SERVER_URL_CROSS_ORIGIN } from './support/common.ts'
import type { TestOptions } from './support/testbed.ts'

const KEYCLOAK_VERSION = 'latest'

export default defineConfig<TestOptions>({
  fullyParallel: true,
  webServer: [{
    command: `podman run -p 8080:8080 -p 9000:9000 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HEALTH_ENABLED=true --pull=newer quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} start-dev`,
    url: 'http://localhost:9000/health/live',
    stdout: 'pipe',
    reuseExistingServer: true,
    gracefulShutdown: {
      // Podman requires a termination signal to stop.
      signal: 'SIGTERM',
      timeout: 5000
    }
  }, {
    command: 'npm run app',
    port: 3000,
    stdout: 'pipe'
  }],
  projects: [
    {
      name: 'Chrome',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: APP_URL.origin
      }
    },
    {
      name: 'Firefox',
      use: {
        ...devices['Desktop Firefox'],
        baseURL: APP_URL.origin
      }
    },
    {
      name: 'Firefox - Cross origin',
      use: {
        ...devices['Desktop Firefox'],
        baseURL: APP_URL_CROSS_ORIGIN.origin,
        appUrl: APP_URL_CROSS_ORIGIN,
        authServerUrl: AUTH_SERVER_URL_CROSS_ORIGIN,
        strictCookies: true,
        launchOptions: {
          firefoxUserPrefs: {
            'network.cookie.cookieBehavior': 1
          }
        }
      }
    }
  ]
})
