import { KeycloakAdapter, KeycloakAdapterContext } from "../keycloak.js";

/**
 * Creates a Cordova adapter for Keycloak authentication.
 * This adapter uses the cordova-plugin-inappbrowser for authentication flows.
 *
 * @param context - Adapter context provided by Keycloak
 * @returns Cordova adapter implementation
 */
export function createCordovaAdapter(
  context: KeycloakAdapterContext
): KeycloakAdapter;
