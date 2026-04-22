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

/**
 * Replaces each listed method on the instance with a bound wrapper that
 * emits a deprecation warning when called with an unbound `this`.
 * @param {object} instance
 * @param {string} code
 * @param {string[]} methods
 */
export function deprecatedBoundMethods (instance, code, methods) {
  for (const name of methods) {
    const original = instance[name]
    instance[name] = function (...args) {
      if (this !== instance) {
        logDeprecation(
          `${code}:${name}`,
          `Calling '${name}()' without a bound 'this' is deprecated and will stop working in a future major version.`
        )
      }
      return original.apply(instance, args)
    }
  }
}
