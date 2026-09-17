'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');

const { ConnectionStore } = require('../connectionStore');
const { redeemDesktopAccess, RedemptionFailed } = require('../labApi');

const PARAMETERS = {
  hostname: '10.10.10.42',
  port: '3389',
  username: 'student',
  password: 'an-uncommon-desktop-password',
};

test('a handle returns its settings exactly once', () => {
  const store = new ConnectionStore();
  const handle = store.put(PARAMETERS);

  assert.deepEqual(store.take(handle), PARAMETERS);
  assert.equal(store.take(handle), null);
});

test('taking a handle removes it whether or not it had expired', () => {
  let clock = 0;
  const store = new ConnectionStore({ ttlMs: 10, now: () => clock });
  const handle = store.put(PARAMETERS);

  clock = 11;
  assert.equal(store.take(handle), null);
  assert.equal(store.size, 0);
});

test('an unknown or malformed handle yields nothing', () => {
  const store = new ConnectionStore();

  for (const candidate of ['', 'not-a-handle', null, undefined, 42, {}]) {
    assert.equal(store.take(candidate), null);
  }
});

test('two handles never collide', () => {
  const store = new ConnectionStore();
  const handles = new Set();
  for (let i = 0; i < 512; i += 1) handles.add(store.put(PARAMETERS));

  assert.equal(handles.size, 512);
});

test('sweeping drops expired entries and keeps live ones', () => {
  let clock = 0;
  const store = new ConnectionStore({ ttlMs: 10, now: () => clock });
  store.put(PARAMETERS);
  clock = 6;
  const live = store.put(PARAMETERS);

  clock = 11;
  store.sweep();

  assert.equal(store.size, 1);
  assert.deepEqual(store.take(live), PARAMETERS);
});

test('redemption presents the service token and the reference', async () => {
  const seen = [];
  const fetchImpl = async (url, options) => {
    seen.push({ url, options });
    return {
      ok: true,
      status: 200,
      json: async () => ({ session_id: 'a1b2c3d4', parameters: PARAMETERS }),
    };
  };

  const body = await redeemDesktopAccess({
    baseUrl: 'http://lab-api:8000',
    serviceToken: 'a-configured-service-token',
    reference: 'a-reference',
    fetchImpl,
  });

  assert.deepEqual(body.parameters, PARAMETERS);
  assert.equal(seen[0].url, 'http://lab-api:8000/api/access/desktop/redeem');
  assert.equal(
    seen[0].options.headers['X-LabsConnect-Service-Token'],
    'a-configured-service-token',
  );
  assert.equal(JSON.parse(seen[0].options.body).token, 'a-reference');
});

test('a spent reference is reported as not redeemable', async () => {
  const fetchImpl = async () => ({ ok: false, status: 404, json: async () => ({}) });

  await assert.rejects(
    redeemDesktopAccess({
      baseUrl: 'http://lab-api:8000',
      serviceToken: 't',
      reference: 'spent',
      fetchImpl,
    }),
    (error) => error instanceof RedemptionFailed && error.status === 404,
  );
});

test('an empty reference never reaches lab-api', async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
    return { ok: true, status: 200, json: async () => ({}) };
  };

  await assert.rejects(
    redeemDesktopAccess({
      baseUrl: 'http://lab-api:8000',
      serviceToken: 't',
      reference: '',
      fetchImpl,
    }),
    RedemptionFailed,
  );
  assert.equal(called, false);
});

test('a response without a target is refused rather than passed to guacd', async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ session_id: 'a1b2c3d4', parameters: {} }),
  });

  await assert.rejects(
    redeemDesktopAccess({
      baseUrl: 'http://lab-api:8000',
      serviceToken: 't',
      reference: 'a-reference',
      fetchImpl,
    }),
    (error) => error.status === 502,
  );
});

test('the client page presents the reference the server expects', () => {
  const fs = require('node:fs');
  const page = fs.readFileSync(`${__dirname}/../public/index.html`, 'utf8');

  assert.match(page, /get\('ref'\)/);
  assert.match(page, /\/api\/token\?ref=/);
  assert.ok(!page.includes('?access='), 'the prototype access parameter is gone');
});

test('the client page drops the reference from the address bar', () => {
  const fs = require('node:fs');
  const page = fs.readFileSync(`${__dirname}/../public/index.html`, 'utf8');

  assert.match(page, /history\.replaceState/);
});
