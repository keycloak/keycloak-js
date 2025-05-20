export interface IAuthorizationRequestMetadata {
  responseIncludeResourceName?: boolean;
  responsePermissionsLimit?: number;
}

export interface IResourcePermission {
  id: string;
  scopes?: string[];
}

export interface IAuthorizationRequest {
  permissions?: IResourcePermission[];
  ticket?: string;
  submitRequest?: boolean;
  metadata?: IAuthorizationRequestMetadata;
  incrementalAuthorization?: boolean;
  claimToken?: string;
  claimTokenFormat?: string;
}

export interface IKeycloakAuthorizationPromise {
  then(
    onGrant: (rpt: string) => void,
    onDeny: () => void,
    onError: (err?: unknown) => void,
  ): void;
}

export interface IKeycloakAuthorizationInstance {
  rpt: string | null;
  authorize(
    authorizationRequest: IAuthorizationRequest,
  ): IKeycloakAuthorizationPromise;
  entitlement(
    resourceServerId: string,
    authorizationRequest?: IAuthorizationRequest,
  ): IKeycloakAuthorizationPromise;
}
