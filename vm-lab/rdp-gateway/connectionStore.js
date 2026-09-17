'use strict';

const crypto = require('crypto');

/**
 * Single-use, short-lived handles for redeemed RDP connections.
 *
 * This store exists because guacamole-lite resolves connection settings
 * synchronously. Server.newConnection constructs a ClientConnection, which
 * calls processConnectionSettings inside its constructor, and then calls
 * connect() on the very next line with no await in between. A callback that
 * resolves asynchronously, such as one making an HTTP call to lab-api, loses
 * that race: guacd is handed the unresolved settings.
 *
 * So the lab-api redemption happens earlier, on the HTTP token request, and
 * the result waits here under a fresh handle until the WebSocket handshake
 * collects it. The handshake lookup is a synchronous Map read.
 *
 * Both steps are single-use. The lab-api reference is consumed by the
 * statement that reads it, and the handle below is deleted by the read that
 * returns it, so neither can be replayed.
 *
 * The cost is that the gateway holds connection state for the few seconds
 * between the two steps, which pins a browser to the instance that issued
 * its handle. One shared gateway deployment satisfies that. Running several
 * requires moving this store out of process first.
 */
class ConnectionStore {
  constructor({ ttlMs = 30_000, now = () => Date.now() } = {}) {
    this.ttlMs = ttlMs;
    this.now = now;
    this.entries = new Map();
  }

  put(settings) {
    const handle = crypto.randomBytes(24).toString('base64url');
    this.entries.set(handle, { settings, expiresAt: this.now() + this.ttlMs });
    return handle;
  }

  take(handle) {
    if (typeof handle !== 'string' || handle.length === 0) return null;
    const entry = this.entries.get(handle);
    if (!entry) return null;
    this.entries.delete(handle);
    if (entry.expiresAt <= this.now()) return null;
    return entry.settings;
  }

  sweep() {
    const now = this.now();
    for (const [handle, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(handle);
    }
  }

  get size() {
    return this.entries.size;
  }
}

module.exports = { ConnectionStore };
