import type { IEndpoints } from "./helpers.js";

export const setupOidcEndpoints = (
  baseUrl: string,
  realm: string,
  oidcConfig?: any,
): IEndpoints => {
  if (!oidcConfig)
    return {
      authorize: () =>
        `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/auth`,
      token: () =>
        `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`,
      logout: () =>
        `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/logout`,
      checkSessionIframe: () =>
        `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/login-status-iframe.html`,
      thirdPartyCookiesIframe: () =>
        `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/3p-cookies/step1.html`,
      register: () =>
        `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/registrations`,
      userinfo: () =>
        `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/userinfo`,
    };

  return {
    authorize: () => oidcConfig.authorization_endpoint,
    token: () => oidcConfig.token_endpoint,
    logout: () => {
      if (!oidcConfig.end_session_endpoint)
        throw new Error("Not supported by OIDC server");
      return oidcConfig.end_session_endpoint;
    },
    checkSessionIframe: () => {
      if (!oidcConfig.check_session_iframe)
        throw new Error("Not supported by OIDC server");
      return oidcConfig.check_session_iframe;
    },
    thirdPartyCookiesIframe: () =>
      `${baseUrl}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/3p-cookies/step1.html`,
    register: () => {
      throw new Error("Register page not supported in standard OIDC mode");
    },
    userinfo: () => {
      if (!oidcConfig.userinfo_endpoint)
        throw new Error("Not supported by OIDC server");
      return oidcConfig.userinfo_endpoint;
    },
  };
};
