// @ts-check
/**
 * @import { DPoPState, DPoPSignatureProviderOptions } from "./keycloak-dpop.ts"
 */

/** @enum {string} */
export const BrowserSignatureAlgs = {
  ES256: 'ES256',
  ES384: 'ES384',
  ES512: 'ES512',
  EdDSA: 'EdDSA'
}

const DB_VERSION = 1
const STORE_NAME = 'main'
const STATE_KEY = 'dpopState'

/** @type {Record<string, EcKeyGenParams | AlgorithmIdentifier>} */
const KEY_GEN_PARAMS = {
  ES256: { name: 'ECDSA', namedCurve: 'P-256' },
  ES384: { name: 'ECDSA', namedCurve: 'P-384' },
  ES512: { name: 'ECDSA', namedCurve: 'P-521' },
  EdDSA: { name: 'Ed25519' }
}

/** @type {Record<string, EcdsaParams | AlgorithmIdentifier>} */
const SIGN_PARAMS = {
  ES256: { name: 'ECDSA', hash: 'SHA-256' },
  ES384: { name: 'ECDSA', hash: 'SHA-384' },
  ES512: { name: 'ECDSA', hash: 'SHA-512' },
  EdDSA: { name: 'Ed25519' }
}

/** Fallback order when EdDSA is unsupported */
const ECDSA_FALLBACK_ORDER = [
  BrowserSignatureAlgs.ES256,
  BrowserSignatureAlgs.ES384,
  BrowserSignatureAlgs.ES512
]

/**
 * Creates a safe database name from issuer and clientId.
 * Uses SHA-256 hash of both issuer and clientId to avoid special characters
 * and prevent injection attacks via malicious clientId values.
 * @param {string} issuer - The authorization server issuer URL
 * @param {string} clientId - The OIDC client identifier
 * @returns {Promise<string>} A sanitized database name
 */
async function createDbName(issuer, clientId) {
  const encoder = new TextEncoder()

  // Hash issuer
  const issuerData = encoder.encode(issuer)
  const issuerHashBuffer = await crypto.subtle.digest('SHA-256', issuerData)
  const issuerHashArray = new Uint8Array(issuerHashBuffer)
  const issuerHash = Array.from(issuerHashArray.slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  // Hash clientId to prevent special character issues and injection
  const clientData = encoder.encode(clientId)
  const clientHashBuffer = await crypto.subtle.digest('SHA-256', clientData)
  const clientHashArray = new Uint8Array(clientHashBuffer)
  const clientHash = Array.from(clientHashArray.slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')

  return `dpop:${issuerHash}:${clientHash}`
}

/**
 * Manages persistent storage of DPoP key pairs and nonces in IndexedDB.
 * Falls back to in-memory storage when IndexedDB is unavailable.
 *
 * Database is named using a hash of the issuer URL + clientId to ensure
 * isolation between different authorization servers.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9449
 */
class DPoPStoreManager {
  /** @type {string} */
  #dbName = ''

  /** @type {IDBDatabase | null} */
  #db = null

  /** @type {boolean} */
  #useMemoryFallback = false

  /** @type {DPoPState | undefined} */
  #memoryStore = undefined

  /** @type {string} */
  #issuer

  /** @type {string} */
  #clientId

  /** @type {boolean} */
  #strictStorage

  /**
   * @param {string} issuer - The authorization server issuer URL
   * @param {string} clientId - The OIDC client identifier
   * @param {boolean} [strictStorage=false] - If true, throws error when IndexedDB is unavailable instead of falling back to memory
   */
  constructor(issuer, clientId, strictStorage = false) {
    this.#issuer = issuer
    this.#clientId = clientId
    this.#strictStorage = strictStorage
  }

  /**
   * Initialize the store manager. Must be called before other operations.
   * @returns {Promise<DPoPStoreManager>}
   */
  async init() {
    if (this.#db || this.#useMemoryFallback) {
      return this // Already initialized
    }

    try {
      this.#dbName = await createDbName(this.#issuer, this.#clientId)
      this.#db = await this.#openDatabase()
    } catch (error) {
      if (this.#strictStorage) {
        throw new Error('DPoP requires IndexedDB for secure key storage, but it is unavailable.', { cause: error })
      }
      console.warn('[KEYCLOAK] IndexedDB unavailable, falling back to in-memory storage:', error)
      this.#useMemoryFallback = true
    }
    return this
  }

  /**
   * Opens or creates the IndexedDB database.
   * @returns {Promise<IDBDatabase>}
   */
  #openDatabase() {
    return new Promise((resolve, reject) => {
      if (typeof indexedDB === 'undefined') {
        reject(new Error('IndexedDB is not available'))
        return
      }

      const request = indexedDB.open(this.#dbName, DB_VERSION)

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve(request.result)
      }

      request.onupgradeneeded = (event) => {
        /** @type {IDBDatabase} */
        const db = /** @type {IDBOpenDBRequest} */ (event.target).result
        const oldVersion = event.oldVersion

        // Version 0 -> 1: Initial schema creation
        if (oldVersion < 1) {
          db.createObjectStore(STORE_NAME)
        }

        // Future migrations:
        // if (oldVersion < 2) {
        //   // Example: Add an index to the store
        //   const store = event.target.transaction.objectStore(STORE_NAME)
        //   store.createIndex('indexName', 'keyPath')
        // }
      }
    })
  }

  /**
   * Retrieve the stored key pair and nonce.
   * @returns {Promise<DPoPState | undefined>}
   */
  async get() {
    if (this.#useMemoryFallback) {
      return this.#memoryStore
    }

    if (!this.#db) {
      throw new Error('DPoPStoreManager not initialized. Call init() first.')
    }

    return new Promise((resolve, reject) => {
      const transaction = /** @type {IDBDatabase} */ (this.#db).transaction(STORE_NAME, 'readonly')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.get(STATE_KEY)

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve(request.result)
      }
    })
  }

  /**
   * Store or overwrite the key pair and optional nonce.
   * @param {DPoPState} state - The state to store
   * @returns {Promise<void>}
   */
  async set(state) {
    if (this.#useMemoryFallback) {
      this.#memoryStore = state
      return
    }

    if (!this.#db) {
      throw new Error('DPoPStoreManager not initialized. Call init() first.')
    }

    return new Promise((resolve, reject) => {
      const transaction = /** @type {IDBDatabase} */ (this.#db).transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.put(state, STATE_KEY)

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Delete all stored data. Called on logout.
   * @returns {Promise<void>}
   */
  async flush() {
    if (this.#useMemoryFallback) {
      this.#memoryStore = undefined
      return
    }

    if (!this.#db) {
      throw new Error('DPoPStoreManager not initialized. Call init() first.')
    }

    return new Promise((resolve, reject) => {
      const transaction = /** @type {IDBDatabase} */ (this.#db).transaction(STORE_NAME, 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const request = store.delete(STATE_KEY)

      request.onerror = () => {
        reject(request.error)
      }

      request.onsuccess = () => {
        resolve()
      }
    })
  }

  /**
   * Update only the nonce while preserving existing keys.
   * Convenience method for handling DPoP-Nonce header responses.
   * @param {string} nonce - The new nonce from the authorization server
   * @returns {Promise<void>}
   * @throws {Error} If nonce fails validation
   */
  async updateNonce(nonce) {
    // Validate nonce to prevent DoS and injection attacks
    const MAX_NONCE_LENGTH = 512
    // RFC 9449 doesn't specify format, but nonces should be printable ASCII for HTTP headers
    const VALID_NONCE_PATTERN = /^[\x21-\x7E]+$/

    if (typeof nonce !== 'string' || nonce.length === 0) {
      throw new Error('DPoP nonce must be a non-empty string')
    }
    if (nonce.length > MAX_NONCE_LENGTH) {
      throw new Error(`DPoP nonce exceeds maximum length of ${MAX_NONCE_LENGTH} characters`)
    }
    if (!VALID_NONCE_PATTERN.test(nonce)) {
      throw new Error('DPoP nonce contains invalid characters')
    }

    const state = await this.get()
    if (state) {
      state.nonce = nonce
      await this.set(state)
    }
  }

  /**
   * Close the database connection.
   */
  close() {
    if (this.#db) {
      this.#db.close()
      this.#db = null
    }
  }
}

export class DPoPSignatureProvider {
  /**@type {BrowserSignatureAlgs} */
  #alg;
  /**@type {DPoPStoreManager} */
  #store;
  /** @type {string[]} */
  #serverAllowedAlgorithms;
  /** @type {Map<string, string>} Resource server nonces keyed by origin */
  #resourceNonces = new Map();
  /**
   * @param {DPoPSignatureProviderOptions} options
   */
  constructor(options) {
    const {
      issuerUrl,
      clientId,
      serverSupportedAlgorithms,
      requestedAlgorithm,
      strictStorage = false
    } = options;

    // Check for Web Crypto API availability
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      throw new Error('DPoP requires Web Crypto API (crypto.subtle) which is not available in this environment.');
    }

    // Validate required options
    if (!issuerUrl) {
      throw new Error('DPoP requires issuerUrl');
    }
    if (!clientId) {
      throw new Error('DPoP requires clientId');
    }
    if (!serverSupportedAlgorithms || !Array.isArray(serverSupportedAlgorithms)) {
      throw new Error('DPoP requires serverSupportedAlgorithms array');
    }
    this.#serverAllowedAlgorithms = serverSupportedAlgorithms;

    let chosenAlgorithm = BrowserSignatureAlgs.ES256; // default value (due to high availability in browsers)

    if (requestedAlgorithm !== undefined) {
      // Check to see if requestedAlgorithm is supported by the server
      if (!this.#serverAllowedAlgorithms.includes(requestedAlgorithm)) {
        throw new Error(`Requested algorithm '${requestedAlgorithm}' is not supported by the server. Server supports: ${this.#serverAllowedAlgorithms.join(', ')}`);
      }

      chosenAlgorithm = requestedAlgorithm
    }

    this.#alg = chosenAlgorithm;

    this.#store = new DPoPStoreManager(issuerUrl.toString(), clientId, strictStorage);
  }

  async init() {
    await this.#store.init();

    // Check for existing keys or generate new ones
    let state = await this.#store.get()
    if (state) {
      const expectedParams = /** @type {EcKeyGenParams & Algorithm} */ (KEY_GEN_PARAMS[this.#alg])
      const storedAlg = /** @type {EcKeyAlgorithm} */ (state.keys.publicKey.algorithm)
      if (storedAlg.name !== expectedParams.name
        || (expectedParams.namedCurve && storedAlg.namedCurve !== expectedParams.namedCurve)) {
        console.warn('[KEYCLOAK] Stored DPoP key algorithm does not match requested algorithm, regenerating key pair.')
        await this.#store.flush()
        state = undefined
      }
    }
    if (!state) {
      const keys = await this.#generateKeyPair()
      state = { keys }
      await this.#store.set(state);
    }
  }

  /**
   * @returns {Promise<CryptoKeyPair>}
   */
  async #generateKeyPair() {
    const params = KEY_GEN_PARAMS[this.#alg]
    if (!params) {
      throw new Error(`Unknown signature algorithm: ${this.#alg}`)
    }

    try {
      return /** @type {CryptoKeyPair} */ (
        await crypto.subtle.generateKey(params, false, ['sign'])
      )
    } catch (ex) {
      if (!(ex instanceof DOMException && ex.name === 'NotSupportedError')) {
        throw ex
      }
      // Only EdDSA needs fallback; ECDSA is universally supported
      if (this.#alg !== BrowserSignatureAlgs.EdDSA) {
        throw ex
      }
      // Find the next available algorithm that both the browser and server support
      const fallback = ECDSA_FALLBACK_ORDER.find(alg =>
        this.#serverAllowedAlgorithms.includes(alg)
      )
      if (!fallback) {
        throw new Error('No supported algorithm available in this browser')
      }
      this.#alg = fallback
      return this.#generateKeyPair()
    }
  }
  /**
   * @param {Uint8Array<ArrayBuffer>} msg
   * @param {CryptoKey} key
   * @returns {Promise<ArrayBuffer>}
   */
  async #sign(msg, key) {
    const params = SIGN_PARAMS[this.#alg]
    if (!params) {
      throw new Error(`Unknown signature algorithm: ${this.#alg}`)
    }
    return await crypto.subtle.sign(params, key, msg)
  }

  /**
   * Clear all stored DPoP state (keys and nonce) for this client. Called on logout.
   * Only affects the keys for this specific issuer+clientId combination.
   * @returns {Promise<void>}
   */
  async flush() {
    await this.#store.flush()
  }

  /**
   * Get the stored authorization server nonce.
   * @returns {Promise<string | undefined>}
   */
  async getAuthServerNonce() {
    const state = await this.#store.get()
    return state?.nonce
  }

  /**
   * Update the authorization server nonce. Called after receiving DPoP-Nonce header.
   * @param {string} nonce
   * @returns {Promise<void>}
   */
  async updateAuthServerNonce(nonce) {
    await this.#store.updateNonce(nonce)
  }

  /**
   * Get the stored resource server nonce for a given origin.
   * @param {string} origin - The resource server origin (e.g., "https://api.example.com")
   * @returns {string | undefined} The stored nonce, or undefined if none exists
   */
  getResourceServerNonce(origin) {
    return this.#resourceNonces.get(origin)
  }

  /**
   * Update the resource server nonce for a given origin. Called after receiving DPoP-Nonce header.
   * Silently ignores invalid nonces to prevent DoS attacks.
   * @param {string} origin - The resource server origin
   * @param {string} nonce - The nonce from the DPoP-Nonce response header
   */
  updateResourceServerNonce(origin, nonce) {
    // Validate nonce to prevent DoS and injection attacks
    const MAX_NONCE_LENGTH = 512
    const VALID_NONCE_PATTERN = /^[\x21-\x7E]+$/

    if (typeof nonce !== 'string' || nonce.length === 0) return
    if (nonce.length > MAX_NONCE_LENGTH) return
    if (!VALID_NONCE_PATTERN.test(nonce)) return

    this.#resourceNonces.set(origin, nonce)
  }

  /**
   * @param {string} url
   * @param {string} httpMethod
   * @param {string} [accessToken] Access token if calling resource server
   * @param {string} [nonce] Server-provided nonce
   * @returns {Promise<string>}
   */
  async generateDPoPProof(url, httpMethod, accessToken, nonce) {
    const payload = {
        jti: crypto.randomUUID(),
        htm: httpMethod,
        htu: (() => {
            const urlObj = new URL(url);
            return urlObj.origin + urlObj.pathname;
        })(),
        iat: Math.floor(Date.now() / 1000), // TODO - Get server time here instead of local time

        ...(accessToken !== undefined && {
            ath: base64UrlEncodeBuffer(await sha256Digest(accessToken))
        }),

        ...(nonce !== undefined && { nonce })
    }

    const state = await this.#store.get() 
    if(state === undefined) throw new Error('DPoP not initialized')
    const exportedJwk = await crypto.subtle.exportKey("jwk", state.keys.publicKey);
    const header = {
        alg: this.#alg,
        typ: "dpop+jwt",
        // Note: `y` is undefined for EdDSA/OKP keys (RFC 8037) but present for EC keys.
        // JSON.stringify omits undefined values, so this produces valid JWKs for both.
        jwk: {
            crv: exportedJwk.crv,
            kty: exportedJwk.kty,
            x: exportedJwk.x,
            y: exportedJwk.y
        }
    };

    const te = new TextEncoder();
    const unsignedToken = `${base64UrlEncodeBuffer(te.encode(JSON.stringify(header)))}.${base64UrlEncodeBuffer(te.encode(JSON.stringify(payload)))}`
    const signature = await this.#sign(te.encode(unsignedToken), state.keys.privateKey);
    return `${unsignedToken}.${base64UrlEncodeBuffer(signature)}`
  }
}

/**
 * @param {string} message
 * @see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#basic_example
 */
async function sha256Digest (message) {
  const encoder = new TextEncoder()
  const data = encoder.encode(message)

  if (typeof crypto === 'undefined' || typeof crypto.subtle === 'undefined') {
    throw new Error('Web Crypto API is not available.')
  }

  return await crypto.subtle.digest('SHA-256', data)
}

/**
 * @param {ArrayBuffer | Uint8Array} buffer
 */
function base64UrlEncodeBuffer(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  const binary = String.fromCharCode(...bytes)
  
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}