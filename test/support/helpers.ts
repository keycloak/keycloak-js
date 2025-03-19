import type CredentialRepresentation from '@keycloak/keycloak-admin-client/lib/defs/credentialRepresentation.ts'
import { adminClient } from './admin-client.ts'
import { APP_HOST, AUTHORIZED_PASSWORD, AUTHORIZED_USERNAME, CLIENT_ID, UNAUTHORIZED_PASSWORD, UNAUTHORIZED_USERNAME } from './common.ts'

export async function createTestResources (): Promise<string> {
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
    redirectUris: [`${APP_HOST}/*`],
    webOrigins: [APP_HOST],
    publicClient: true
  })

  return realmName
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
