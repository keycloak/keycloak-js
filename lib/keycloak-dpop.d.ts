/** Taken from {@link https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto#supported_algorithms here} - excluding RSA. */
export enum BrowserSignatureAlgs {
  ES256 = 'ES256',
  ES384 = 'ES384',
  ES512 = 'ES512',
  EdDSA = 'EdDSA'
}

/**
 * State stored in IndexedDB for DPoP.
 */
export interface DPoPState {
  /** The browser-native crypto key pair */
  keys: CryptoKeyPair
  /** Authorization server's DPoP nonce */
  nonce?: string
}

/**
 * Options for creating a DPoPSignatureProvider.
 */
export interface DPoPSignatureProviderOptions {
  /** The authorization server issuer URL */
  issuerUrl: URL
  /** The OIDC client identifier */
  clientId: string
  /** Algorithms supported by the server (from dpop_signing_alg_values_supported) */
  serverSupportedAlgorithms: string[]
  /** Preferred signing algorithm (defaults to ES256) */
  requestedAlgorithm?: BrowserSignatureAlgs
  /** If true, throws when IndexedDB unavailable instead of using memory fallback */
  strictStorage?: boolean
}

/**
 * Provides DPoP proof generation for OAuth 2.0 token binding.
 * @see https://datatracker.ietf.org/doc/html/rfc9449
 */
export class DPoPSignatureProvider {
  constructor(options: DPoPSignatureProviderOptions)

  /** Initialize the provider. Must be called before generating proofs. */
  init(): Promise<void>

  /**
   * Clear all stored DPoP state (keys and nonce) for this client. Called on logout.
   * Only affects the keys for this specific issuer+clientId combination.
   */
  flush(): Promise<void>

  /**
   * Get the stored authorization server nonce.
   * @returns The stored nonce, or undefined if none exists
   */
  getAuthServerNonce(): Promise<string | undefined>

  /**
   * Update the authorization server nonce. Called after receiving DPoP-Nonce header.
   * @param nonce - The nonce from the DPoP-Nonce response header
   */
  updateAuthServerNonce(nonce: string): Promise<void>

  /**
   * Get the stored resource server nonce for a given origin.
   * @param origin - The resource server origin (e.g., "https://api.example.com")
   * @returns The stored nonce, or undefined if none exists
   */
  getResourceServerNonce(origin: string): string | undefined

  /**
   * Update the resource server nonce for a given origin. Called after receiving DPoP-Nonce header.
   * @param origin - The resource server origin
   * @param nonce - The nonce from the DPoP-Nonce response header
   */
  updateResourceServerNonce(origin: string, nonce: string): void

  /**
   * Generate a DPoP proof JWT for a request.
   * @param url - The HTTP target URI
   * @param httpMethod - The HTTP method (GET, POST, etc.)
   * @param accessToken - Access token to bind (for resource server requests)
   * @param nonce - Server-provided nonce
   * @returns The DPoP proof JWT
   */
  generateDPoPProof(url: string, httpMethod: string, accessToken?: string, nonce?: string): Promise<string>
}
