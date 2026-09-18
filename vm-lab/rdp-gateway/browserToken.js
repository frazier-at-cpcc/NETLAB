'use strict';

const crypto = require('crypto');

/**
 * The token a browser holds.
 *
 * guacamole-lite requires an encrypted token and will not accept a bare
 * value, so the handle travels inside one. The encryption is a framework
 * requirement rather than the security boundary. The boundary is the
 * plaintext: it carries a connection type and a single-use handle, and never
 * a hostname, port, username, or password.
 *
 * This lives in its own module so that property can be asserted directly
 * against the bytes a browser would receive, rather than inferred from the
 * code that builds them.
 */
function encryptHandleToken(key, handle) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  // The handle must sit under connection.settings. ClientConnection's
  // mergeConnectionOptions rebuilds connection from
  // connectionDefaultSettings[type] merged with connection.settings, so any
  // key placed directly on connection is discarded before the callback runs.
  const payload = JSON.stringify({
    connection: { type: 'rdp', settings: { handle } },
  });
  const value = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  return Buffer.from(
    JSON.stringify({ iv: iv.toString('base64'), value: value.toString('base64') }),
  ).toString('base64');
}

/** Test seam. Reverses encryptHandleToken so a test can read the plaintext. */
function decryptHandleToken(key, token) {
  const outer = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(key),
    Buffer.from(outer.iv, 'base64'),
  );
  return Buffer.concat([
    decipher.update(Buffer.from(outer.value, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

module.exports = { encryptHandleToken, decryptHandleToken };
