import { defineConfig, devices, type PlaywrightTestConfig } from '@playwright/test'
import { APP_URL, APP_URL_CROSS_ORIGIN, AUTH_SERVER_URL_CROSS_ORIGIN } from './support/common.ts'
import type { TestOptions } from './support/testbed.ts'
import { execSync } from 'child_process'

const KEYCLOAK_VERSION = 'latest'

const DEFAULT_KEYCLOAK_SERVER_CONFIG: PlaywrightTestConfig["webServer"] = {
    command: "", // Nothing, has to be started before.
    url: 'http://localhost:9000/health/live',
    stdout: 'pipe',
    reuseExistingServer: true, 
};

const CONTAINER_ENGINE_CONFIG: Record<string, Partial<PlaywrightTestConfig["webServer"]>> = {
  podman: {
    command: `podman run -p 8080:8080 -p 9000:9000 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HEALTH_ENABLED=true --pull=newer quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} start-dev`,
    gracefulShutdown: {
      // Podman requires a termination signal to stop.
      signal: 'SIGTERM',
      timeout: 5000
    }
  },
  docker: {
    command: `docker run -p 8080:8080 -p 9000:9000 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin -e KC_HEALTH_ENABLED=true --pull=always quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} start-dev`,
  }
};

function detectContainerEngine() {
  try {
    execSync('podman --version && podman info', { stdio: 'ignore' });
    return 'podman';
  } catch {}

  try {
    execSync('docker --version && docker info', { stdio: 'ignore' });
    return 'docker';
  } catch {}
}

const containerEngine = detectContainerEngine();
if (!containerEngine) {
  console.warn('No container engine found. Cannot automatically start Keycloak Server.');
}

export default defineConfig<TestOptions>({
  fullyParallel: true,
  webServer: [{
    ...DEFAULT_KEYCLOAK_SERVER_CONFIG,
    ...(containerEngine ? CONTAINER_ENGINE_CONFIG[containerEngine] : {}),
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
