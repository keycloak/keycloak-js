import { defineConfig } from '@playwright/test'
import { APP_HOST } from './support/common.ts'

const KEYCLOAK_VERSION = 'latest'

export default defineConfig({
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
  use: {
    baseURL: APP_HOST
  }
})
