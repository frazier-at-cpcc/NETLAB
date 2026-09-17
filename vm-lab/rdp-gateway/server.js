'use strict';

const crypto = require('crypto');
const express = require('express');
const GuacamoleLite = require('guacamole-lite');

const { ConnectionStore } = require('./connectionStore');
const { redeemDesktopAccess, RedemptionFailed } = require('./labApi');

const HTTP_PORT = Number(process.env.HTTP_PORT || 8080);
const WS_PORT = Number(process.env.WS_PORT || 8081);
const WS_PUBLIC_URL = process.env.WS_PUBLIC_URL;
const GUACD_HOST = process.env.GUACD_HOST || 'guacd';
const TOKEN_KEY = process.env.GUACAMOLE_TOKEN_KEY;
const LAB_API_URL = process.env.LAB_API_URL;
const LAB_API_SERVICE_TOKEN = process.env.LAB_API_SERVICE_TOKEN;
const HANDLE_TTL_MS = Number(process.env.HANDLE_TTL_MS || 30_000);

// The gateway holds no RDP target of its own. RDP_HOST, RDP_USERNAME,
// RDP_PASSWORD, and PROTOTYPE_ACCESS_TOKEN belonged to the prototype and are
// deliberately gone: a target now arrives only from lab-api, for one
// connection, against one reference presented by one student.
if (!TOKEN_KEY || Buffer.byteLength(TOKEN_KEY) !== 32)
  throw new Error('a 32-byte GUACAMOLE_TOKEN_KEY is required');
if (!LAB_API_URL || !LAB_API_SERVICE_TOKEN)
  throw new Error('LAB_API_URL and LAB_API_SERVICE_TOKEN are required');

const store = new ConnectionStore({ ttlMs: HANDLE_TTL_MS });
setInterval(() => store.sweep(), HANDLE_TTL_MS).unref();

/**
 * guacamole-lite requires an encrypted token and will not accept a bare
 * value, so the handle travels inside one. The encryption is a framework
 * requirement rather than the security boundary. The boundary is that the
 * plaintext holds a single-use handle and no host, user, or password.
 */
function encryptToken(payload) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(TOKEN_KEY), iv);
  const value = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return Buffer.from(JSON.stringify({ iv: iv.toString('base64'), value: value.toString('base64') })).toString('base64');
}

new GuacamoleLite({ port: WS_PORT, host: '0.0.0.0' }, { host: GUACD_HOST, port: 4822 }, {
  crypt: { cypher: 'AES-256-CBC', key: TOKEN_KEY },
  connectionDefaultSettings: {
    rdp: { 'ignore-cert': true, 'enable-drive': false, 'enable-printing': false, 'enable-audio': false },
  },
  callbacks: {
    // Synchronous by necessity. See connectionStore.js for why an async
    // callback here is silently ignored by guacamole-lite 1.2.0.
    processConnectionSettings: (settings, callback) => {
      const handle = settings && settings.connection && settings.connection.handle;
      const resolved = store.take(handle);
      if (!resolved) {
        return callback(new Error('no live connection for this handle'));
      }
      return callback(undefined, {
        ...settings,
        connection: { ...settings.connection, ...resolved, handle: undefined },
      });
    },
  },
});

const app = express();
app.use(express.static('public'));
app.get('/health', (_req, res) => res.json({ status: 'ready' }));

app.get('/api/token', async (req, res) => {
  const reference = req.query.ref;
  try {
    const redeemed = await redeemDesktopAccess({
      baseUrl: LAB_API_URL,
      serviceToken: LAB_API_SERVICE_TOKEN,
      reference: typeof reference === 'string' ? reference : '',
    });
    const handle = store.put(redeemed.parameters);
    const token = encryptToken({ connection: { type: 'rdp', handle } });
    const websocket = WS_PUBLIC_URL || `${req.protocol === 'https' ? 'wss' : 'ws'}://${req.hostname}:${WS_PORT}/`;
    console.log(`desktop_handle_issued session=${redeemed.session_id}`);
    return res.json({ token, websocket });
  } catch (error) {
    const status = error instanceof RedemptionFailed ? error.status : 500;
    // The message is deliberately uniform. A student who guesses a reference
    // learns nothing about whether it named a real session.
    console.warn(`desktop_handle_refused status=${status}`);
    return res.status(status === 404 ? 403 : status).json({ error: 'unavailable' });
  }
});

app.listen(HTTP_PORT, '0.0.0.0', () => console.log(`rdp_gateway_ready ${HTTP_PORT}/${WS_PORT}`));
