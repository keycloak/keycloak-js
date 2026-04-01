import AdminClient from '@keycloak/keycloak-admin-client'
import { ADMIN_PASSWORD, ADMIN_USERNAME, AUTH_SERVER_URL } from './common.ts'

// Trailing slashes can cause issues with requests from the Admin Client.
// See: https://github.com/keycloak/keycloak/issues/44269
const authServerUrl = AUTH_SERVER_URL.toString()
const baseUrl = authServerUrl.endsWith('/') ? authServerUrl.slice(0, -1) : authServerUrl

export const adminClient = new AdminClient({ baseUrl })

await adminClient.auth({
  username: ADMIN_USERNAME,
  password: ADMIN_PASSWORD,
  grantType: 'password',
  clientId: 'admin-cli'
})
