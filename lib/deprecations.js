/** @type {Set<string>} */
const emitted = new Set()

/**
 * Emit a deprecation warning. Each code is only warned once per page load.
 * @param {string} code Unique deprecation identifier (e.g. "KC-DEP-001").
 * @param {string} message Human-readable deprecation message.
 */
export function logDeprecation (code, message) {
  if (emitted.has(code)) {
    return
  }

  emitted.add(code)
  console.warn(`[KEYCLOAK] ${code}: ${message}`)
}
