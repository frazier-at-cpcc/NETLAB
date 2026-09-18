'use strict';

/**
 * The guacamole-lite callbacks.
 *
 * These belong in the FOURTH argument of `new GuacamoleLite(...)`, not inside
 * the third. Server.js does `Object.assign({processConnectionSettings: pass
 * through}, callbacks)` on its fourth parameter, so a callbacks object handed
 * to clientOptions is silently ignored and every connection reaches guacd with
 * whatever the token carried. In this design the token carries only a handle,
 * so guacd got no hostname and failed with "DNS lookup failed (incorrect
 * hostname?)" against a target that was reachable the whole time.
 *
 * Kept in its own module so the resolution logic can be tested without
 * starting a server.
 */
function buildCallbacks(store) {
  return {
    // Synchronous by necessity. See connectionStore.js for why an async
    // callback here is silently ignored by guacamole-lite 1.2.0.
    processConnectionSettings: (settings, callback) => {
      const handle = settings && settings.connection && settings.connection.handle;
      const resolved = store.take(handle);
      if (!resolved) {
        return callback(new Error('no live connection for this handle'));
      }
      const connection = { ...settings.connection, ...resolved };
      delete connection.handle;
      return callback(undefined, { ...settings, connection });
    },
  };
}

module.exports = { buildCallbacks };
