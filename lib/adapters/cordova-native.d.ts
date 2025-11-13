import { KeycloakAdapter, KeycloakAdapterContext } from "../keycloak.js";

/**
 * Creates a Cordova Native adapter for Keycloak authentication.
 * This adapter uses native Cordova plugins (cordova-plugin-safariviewcontroller or cordova-plugin-inappbrowser)
 * and is recommended over the standard Cordova adapter for better native integration.
 *
 * @param context - Adapter context provided by Keycloak
 * @returns Cordova Native adapter implementation
 */
export function createCordovaNativeAdapter(
  context: KeycloakAdapterContext
): KeycloakAdapter;
