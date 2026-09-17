const crypto = require('crypto');
const express = require('express');
const GuacamoleLite = require('guacamole-lite');

const HTTP_PORT = Number(process.env.HTTP_PORT || 8080);
const WS_PORT = Number(process.env.WS_PORT || 8081);
const WS_PUBLIC_URL = process.env.WS_PUBLIC_URL;
const GUACD_HOST = process.env.GUACD_HOST || 'guacd';
const ACCESS_TOKEN = process.env.PROTOTYPE_ACCESS_TOKEN;
const RDP_HOST = process.env.RDP_HOST;
const RDP_USERNAME = process.env.RDP_USERNAME;
const RDP_PASSWORD = process.env.RDP_PASSWORD;
const RDP_PORT = Number(process.env.RDP_PORT || 3389);
const TOKEN_KEY = process.env.GUACAMOLE_TOKEN_KEY;

if (!ACCESS_TOKEN || !RDP_HOST || !RDP_USERNAME || !RDP_PASSWORD || !TOKEN_KEY || Buffer.byteLength(TOKEN_KEY) !== 32)
  throw new Error('PROTOTYPE_ACCESS_TOKEN, RDP_*, and a 32-byte GUACAMOLE_TOKEN_KEY are required');

function encryptToken(payload) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(TOKEN_KEY), iv);
  const value = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return Buffer.from(JSON.stringify({ iv: iv.toString('base64'), value: value.toString('base64') })).toString('base64');
}

new GuacamoleLite({ port: WS_PORT, host: '0.0.0.0' }, { host: GUACD_HOST, port: 4822 }, {
  crypt: { cypher: 'AES-256-CBC', key: TOKEN_KEY },
  // GNOME Remote Desktop on RHEL 10 negotiates TLS. "any" lets FreeRDP
  // complete the server's TLS negotiation while retaining Windows support.
  connectionDefaultSettings: { rdp: { security: 'any', 'ignore-cert': true, 'enable-drive': false, 'enable-printing': false, 'enable-audio': false } },
});

const app = express();
app.use(express.static('public'));
app.get('/health', (_req, res) => res.json({ status: 'ready' }));
app.get('/api/token', (req, res) => {
  if (req.query.access !== ACCESS_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  const token = encryptToken({ connection: { type: 'rdp', settings: {
    hostname: RDP_HOST, port: RDP_PORT, username: RDP_USERNAME, password: RDP_PASSWORD,
  } } });
  const websocket = WS_PUBLIC_URL || `${req.protocol === 'https' ? 'wss' : 'ws'}://${req.hostname}:${WS_PORT}/`;
  res.json({ token, websocket });
});
app.listen(HTTP_PORT, '0.0.0.0', () => console.log(`rdp_gateway_ready ${HTTP_PORT}/${WS_PORT}`));
