import type { Keycloak } from "../cloak.js";
import type {
  IAuthorizationRequest,
  IKeycloakAuthorizationInstance,
  IKeycloakAuthorizationPromise,
} from "./types.js";

export class KeycloakAuthorization implements IKeycloakAuthorizationInstance {
  rpt: string | null = null;
  #config: any;
  #keycloak: Keycloak;
  #configPromise: Promise<any> | null = null;

  constructor(keycloak: Keycloak) {
    this.#keycloak = keycloak;
  }

  #initializeConfigIfNeeded = async (): Promise<any> => {
    if (this.#config) return this.#config;
    if (this.#configPromise) return this.#configPromise;
    if (!this.#keycloak.didInitialize)
      throw new Error("The Keycloak instance has not been initialized yet.");
    this.#configPromise = this.#loadConfig(
      this.#keycloak.authServerUrl!,
      this.#keycloak.realm!,
    );
    this.#config = await this.#configPromise;
    return this.#config;
  };

  #loadConfig = async (serverUrl: string, realm: string): Promise<any> => {
    const url = `${serverUrl}/realms/${encodeURIComponent(realm)}/.well-known/uma2-configuration`;
    const response = await fetch(url);
    if (!response.ok)
      throw new Error("Could not obtain configuration from server.");
    return await response.json();
  };

  authorize = (
    authorizationRequest: IAuthorizationRequest,
  ): IKeycloakAuthorizationPromise => {
    return {
      then: async (
        onGrant: (rpt: string) => void,
        onDeny: () => void,
        onError: (err?: unknown) => void,
      ) => {
        try {
          await this.#initializeConfigIfNeeded();
        } catch (error) {
          onError?.(error);
          return;
        }
        if (authorizationRequest && authorizationRequest.ticket) {
          const params = [
            ["grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket"],
            ["client_id", this.#keycloak.clientId!],
            ["ticket", authorizationRequest.ticket],
          ];
          if (authorizationRequest.submitRequest !== undefined)
            params.push([
              "submit_request",
              String(authorizationRequest.submitRequest),
            ]);
          const metadata = authorizationRequest.metadata;
          if (metadata?.responseIncludeResourceName)
            params.push([
              "response_include_resource_name",
              String(metadata.responseIncludeResourceName),
            ]);
          if (metadata?.responsePermissionsLimit)
            params.push([
              "response_permissions_limit",
              String(metadata.responsePermissionsLimit),
            ]);
          if (
            this.rpt &&
            (authorizationRequest.incrementalAuthorization === undefined ||
              authorizationRequest.incrementalAuthorization)
          )
            params.push(["rpt", this.rpt]);
          const request = new XMLHttpRequest();
          request.open("POST", this.#config.token_endpoint, true);
          request.setRequestHeader(
            "Content-type",
            "application/x-www-form-urlencoded",
          );
          request.setRequestHeader(
            "Authorization",
            "Bearer " + this.#keycloak.token,
          );
          request.onreadystatechange = () => {
            if (request.readyState === 4) {
              const status = request.status;
              if (status >= 200 && status < 300) {
                const rpt = JSON.parse(request.responseText).access_token;
                this.rpt = rpt;
                onGrant(rpt);
              } else if (status === 403) {
                onDeny?.();
              } else {
                onError?.();
              }
            }
          };
          request.send(
            params
              .map(
                ([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`,
              )
              .join("&"),
          );
        }
      },
    };
  };

  entitlement = (
    resourceServerId: string,
    authorizationRequest: IAuthorizationRequest = {},
  ): IKeycloakAuthorizationPromise => {
    return {
      then: async (
        onGrant: (rpt: string) => void,
        onDeny: () => void,
        onError: (err?: unknown) => void,
      ) => {
        try {
          await this.#initializeConfigIfNeeded();
        } catch (error) {
          onError?.(error);
          return;
        }
        const params: [string, string][] = [
          ["grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket"],
          ["client_id", this.#keycloak.clientId!],
          ["audience", resourceServerId],
        ];
        if (authorizationRequest.claimToken)
          params.push(["claim_token", authorizationRequest.claimToken]);
        if (authorizationRequest.claimTokenFormat)
          params.push([
            "claim_token_format",
            authorizationRequest.claimTokenFormat,
          ]);
        const permissions = authorizationRequest.permissions ?? [];
        for (const resource of permissions) {
          let permission = resource.id;
          if (resource.scopes && resource.scopes.length > 0) {
            permission += "#" + resource.scopes.join(",");
          }
          params.push(["permission", permission]);
        }
        const metadata = authorizationRequest.metadata;
        if (metadata?.responseIncludeResourceName)
          params.push([
            "response_include_resource_name",
            String(metadata.responseIncludeResourceName),
          ]);
        if (metadata?.responsePermissionsLimit)
          params.push([
            "response_permissions_limit",
            String(metadata.responsePermissionsLimit),
          ]);
        if (this.rpt) params.push(["rpt", this.rpt]);
        const request = new XMLHttpRequest();
        request.open("POST", this.#config.token_endpoint, true);
        request.setRequestHeader(
          "Content-type",
          "application/x-www-form-urlencoded",
        );
        request.setRequestHeader(
          "Authorization",
          "Bearer " + this.#keycloak.token,
        );
        request.onreadystatechange = () => {
          if (request.readyState === 4) {
            const status = request.status;
            if (status >= 200 && status < 300) {
              const rpt = JSON.parse(request.responseText).access_token;
              this.rpt = rpt;
              onGrant(rpt);
            } else if (status === 403) {
              onDeny?.();
            } else {
              onError?.();
            }
          }
        };
        request.send(
          params
            .map(
              ([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`,
            )
            .join("&"),
        );
      },
    };
  };
}
