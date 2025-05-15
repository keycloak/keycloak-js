/*
 *  Copyright 2016 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

import type Keycloak from './keycloak.js'; // Assuming Keycloak class is exported as default

// Interfaces
export interface IKeycloakAuthorizationOptions {
	// Currently no options are passed to the constructor, but defining for future use
	// Example:
	//  token?: string;
	//  rpt?: string;
}

export interface IAuthorizationRequestMetadata {
	responseIncludeResourceName?: boolean;
	responsePermissionsLimit?: number;
}

export interface IAuthorizationRequest {
	ticket: string;
	submitRequest?: boolean;
	metadata?: IAuthorizationRequestMetadata;
	incrementalAuthorization?: boolean;
}

export interface IPermission {
	id: string; // resource_id or resource_name
	scopes?: string[];
}

export interface IEntitlementRequest {
	claimToken?: string;
	claimTokenFormat?: string;
	permissions?: IPermission[];
	metadata?: IAuthorizationRequestMetadata;
}

export interface IUMAConfiguration {
	token_endpoint: string;
	// Add other UMA configuration fields as needed, e.g.:
	// resource_registration_endpoint?: string;
	// policy_endpoint?: string;
	// permission_endpoint?: string;
}

export interface IRptResponse {
	access_token: string; // This is the RPT
	[key: string]: unknown; // Other properties from the response
}

class KeycloakAuthorization {
	readonly #keycloak: Keycloak;
	#rpt: string | null = null;
	#umaConfiguration: IUMAConfiguration | null = null;
	#umaConfigurationPromise: Promise<IUMAConfiguration> | null = null;

	constructor(keycloak: Keycloak, _options?: IKeycloakAuthorizationOptions) {
		this.#keycloak = keycloak;
		// Options are not currently used by the constructor's logic, but kept for future interface consistency
	}

	async #initializeUmaConfiguration(): Promise<IUMAConfiguration> {
		if (this.#umaConfiguration) {
			return this.#umaConfiguration;
		}

		if (this.#umaConfigurationPromise) {
			return this.#umaConfigurationPromise;
		}

		if (!this.#keycloak.authServerUrl || !this.#keycloak.realm) {
			throw new Error('Keycloak instance is not properly configured with authServerUrl and realm.');
		}
		
		// Ensure Keycloak instance itself is initialized if it has relevant async init logic
		// For this refactor, we assume keycloak instance properties like authServerUrl and realm are available post-its-own-init
		// if (!this.#keycloak.didInitialize) { // Assuming 'didInitialize' is a public property on Keycloak
		//  throw new Error('The Keycloak instance has not been initialized yet.');
		// }

		this.#umaConfigurationPromise = KeycloakAuthorization.#loadUmaConfiguration(
			this.#keycloak.authServerUrl,
			this.#keycloak.realm,
		);

		try {
			this.#umaConfiguration = await this.#umaConfigurationPromise;
			return this.#umaConfiguration;
		} finally {
			this.#umaConfigurationPromise = null; // Clear promise once resolved or failed
		}
	}

	public async authorize(authorizationRequest: IAuthorizationRequest): Promise<string> {
		if (!authorizationRequest || !authorizationRequest.ticket) {
			throw new Error('Authorization request must contain a ticket.');
		}

		const config = await this.#initializeUmaConfiguration();

		const params = new URLSearchParams({
			grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
			client_id: this.#keycloak.clientId!,
			ticket: authorizationRequest.ticket,
		});

		if (authorizationRequest.submitRequest !== undefined) {
			params.append('submit_request', String(authorizationRequest.submitRequest));
		}

		if (authorizationRequest.metadata) {
			if (authorizationRequest.metadata.responseIncludeResourceName) {
				params.append(
					'response_include_resource_name',
					String(authorizationRequest.metadata.responseIncludeResourceName),
				);
			}
			if (authorizationRequest.metadata.responsePermissionsLimit) {
				params.append(
					'response_permissions_limit',
					String(authorizationRequest.metadata.responsePermissionsLimit),
				);
			}
		}

		if (this.#rpt && (authorizationRequest.incrementalAuthorization === undefined || authorizationRequest.incrementalAuthorization)) {
			params.append('rpt', this.#rpt);
		}

		try {
			const response = await KeycloakAuthorization.#fetchJson<IRptResponse>(config.token_endpoint, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Authorization: 'Bearer ' + this.#keycloak.token,
				},
				body: params,
			});
			this.#rpt = response.access_token;
			return this.#rpt;
		} catch (error) {
			this.#handleError(error, 'Could not obtain authorization data from server.');
			// #handleError re-throws, so this line won't be reached if it throws.
			// If #handleError is modified to not throw, then a specific throw is needed here.
			throw error; // Re-throw after handling or throw a more specific error
		}
	}

	public async entitlement(resourceServerId: string, entitlementRequest?: IEntitlementRequest): Promise<string> {
		const config = await this.#initializeUmaConfiguration();

		const requestParams: Record<string, string> = {
			grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
			client_id: this.#keycloak.clientId!,
			audience: resourceServerId,
		};

		if (entitlementRequest?.claimToken) {
			requestParams.claim_token = entitlementRequest.claimToken;
			if (entitlementRequest.claimTokenFormat) {
				requestParams.claim_token_format = entitlementRequest.claimTokenFormat;
			}
		}
		
		const permissions = entitlementRequest?.permissions ?? [];
		permissions.forEach(resource => {
			let permissionValue = resource.id;
			if (resource.scopes && resource.scopes.length > 0) {
				permissionValue += '#' + resource.scopes.join(',');
			}
			// For URLSearchParams, multiple values for the same key are handled by appending.
			// However, the original code concatenates them into a single '&permission=' for each.
			// To precisely match, we'd need to append manually or ensure server handles multiple params.
			// For now, assuming server can handle multiple 'permission' query parameters if URLSearchParams creates them.
			// If not, manual string building would be needed for the 'permission' part.
			// The original code does: params += "&permission=" + permission; which means multiple such params.
			// URLSearchParams.append will achieve this.
		});


		const params = new URLSearchParams(requestParams);

		permissions.forEach(resource => {
			let permissionValue = resource.id;
			if (resource.scopes && resource.scopes.length > 0) {
				permissionValue += '#' + resource.scopes.join(',');
			}
			params.append('permission', permissionValue);
		});


		if (entitlementRequest?.metadata) {
			if (entitlementRequest.metadata.responseIncludeResourceName) {
				params.append(
					'response_include_resource_name',
					String(entitlementRequest.metadata.responseIncludeResourceName),
				);
			}
			if (entitlementRequest.metadata.responsePermissionsLimit) {
				params.append(
					'response_permissions_limit',
					String(entitlementRequest.metadata.responsePermissionsLimit),
				);
			}
		}

		if (this.#rpt) {
			params.append('rpt', this.#rpt);
		}

		try {
			const response = await KeycloakAuthorization.#fetchJson<IRptResponse>(config.token_endpoint, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Authorization: 'Bearer ' + this.#keycloak.token,
				},
				body: params,
			});
			this.#rpt = response.access_token;
			return this.#rpt;
		} catch (error) {
			this.#handleError(error, 'Could not obtain entitlement data from server.');
			throw error; 
		}
	}
	
	#handleError(error: unknown, defaultMessage: string): never {
		if (error instanceof Error) {
			console.error(`[KEYCLOAK AUTHZ] ${defaultMessage}`, error.message, error.cause);
			throw new Error(`${defaultMessage}: ${error.message}`, { cause: error.cause });
		}
		console.error(`[KEYCLOAK AUTHZ] ${defaultMessage} An unknown error occurred.`, error);
		throw new Error(`${defaultMessage}: An unknown error occurred.`);
	}

	static async #loadUmaConfiguration(authServerUrl: string, realm: string): Promise<IUMAConfiguration> {
		const url = `${authServerUrl}/realms/${encodeURIComponent(realm)}/.well-known/uma2-configuration`;
		try {
			return await KeycloakAuthorization.#fetchJson<IUMAConfiguration>(url);
		} catch (error) {
			// Create a new error with a more specific message, chaining the original error
			const message = 'Could not load UMA configuration from server.';
			if (error instanceof Error) {
				throw new Error(`${message} Reason: ${error.message}`, { cause: error });
			}
			throw new Error(message);
		}
	}

	static async #fetchJson<T = unknown>(url: string, options?: RequestInit): Promise<T> {
		let response: Response;
		try {
			response = await fetch(url, options);
		} catch (networkError) {
			// Network error (e.g., DNS, TCP connection refused)
			throw new Error('Network error while fetching JSON.', { cause: networkError });
		}

		if (!response.ok) {
			// HTTP error (e.g., 404, 500)
			const errorText = await response.text().catch(() => 'Could not read error response body.');
			throw new Error(`Failed to fetch JSON. Status: ${response.status} ${response.statusText}. Body: ${errorText}`);
		}

		try {
			return (await response.json()) as T;
		} catch (jsonParseError) {
			// JSON parsing error
			throw new Error('Failed to parse JSON response.', { cause: jsonParseError });
		}
	}
}

export default KeycloakAuthorization;
```
