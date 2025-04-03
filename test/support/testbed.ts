import type CredentialRepresentation from '@keycloak/keycloak-admin-client/lib/defs/credentialRepresentation.ts'
import type { Page } from '@playwright/test'
import { test as base } from '@playwright/test'
import { adminClient } from './admin-client.ts'
import { APP_URL, AUTH_SERVER_URL, AUTHORIZED_PASSWORD, AUTHORIZED_USERNAME, CLIENT_ID, UNAUTHORIZED_PASSWORD, UNAUTHORIZED_USERNAME } from './common.ts'
import { TestExecutor, type TestExecutorOptions } from './test-executor.ts'

export interface TestOptions {
  appUrl: URL
  authServerUrl: URL
  strictCookies: boolean
}

export const test = base.extend<TestOptions>({
  appUrl: [APP_URL, { option: true }],
  authServerUrl: [AUTH_SERVER_URL, { option: true }],
  strictCookies: [false, { option: true }]
})

export async function createTestBed (page: Page, options: TestExecutorOptions): Promise<TestExecutor> {
  const { realmName } = await adminClient.realms.create({
    realm: crypto.randomUUID(),
    enabled: true
  })

  await Promise.all([
    adminClient.roles.create({
      realm: realmName,
      name: 'user',
      scopeParamRequired: false
    }),
    adminClient.roles.create({
      realm: realmName,
      name: 'admin',
      scopeParamRequired: false
    })
  ])

  await Promise.all([
    createUserWithCredential({
      realm: realmName,
      enabled: true,
      username: AUTHORIZED_USERNAME,
      firstName: 'Authorized',
      lastName: 'User',
      email: 'test-user@localhost',
      emailVerified: true,
      realmRoles: ['user'],
      clientRoles: {
        'realm-management': ['view-realm', 'manage-users'],
        account: ['view-profile', 'manage-account']
      }
    }, {
      temporary: false,
      type: 'password',
      value: AUTHORIZED_PASSWORD
    }),
    createUserWithCredential({
      realm: realmName,
      enabled: true,
      username: UNAUTHORIZED_USERNAME,
      firstName: 'Unauthorized',
      lastName: 'User',
      email: 'unauthorized@localhost',
      emailVerified: true
    }, {
      temporary: false,
      type: 'password',
      value: UNAUTHORIZED_PASSWORD
    })
  ])

  await adminClient.clients.create({
    realm: realmName,
    enabled: true,
    clientId: CLIENT_ID,
    redirectUris: [`${options.appUrl.origin}/*`],
    webOrigins: [options.appUrl.origin],
    publicClient: true
  })

  return new TestExecutor(page, realmName, options)
}

type CreateUserParams = NonNullable<Parameters<typeof adminClient.users.create>[0]>

async function createUserWithCredential (user: CreateUserParams, credential: CredentialRepresentation): Promise<void> {
  const { id } = await adminClient.users.create(user)

  await adminClient.users.resetPassword({
    realm: user.realm,
    id,
    credential
  })
}
