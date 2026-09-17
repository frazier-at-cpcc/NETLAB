'use strict';

/**
 * The gateway's only path to a connection target.
 *
 * It holds no RDP host, user, or password of its own. It presents the
 * browser's opaque reference to lab-api over the internal service token and
 * receives the guacd parameters for exactly one connection.
 *
 * Nothing here logs the reference or the parameters. The reference opens a
 * desktop, and the parameters carry the password.
 */
class RedemptionFailed extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'RedemptionFailed';
    this.status = status;
  }
}

async function redeemDesktopAccess({
  baseUrl,
  serviceToken,
  reference,
  fetchImpl = fetch,
}) {
  if (!reference) throw new RedemptionFailed('no reference presented', 400);

  let response;
  try {
    response = await fetchImpl(`${baseUrl}/api/access/desktop/redeem`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-LabsConnect-Service-Token': serviceToken,
      },
      body: JSON.stringify({ token: reference }),
    });
  } catch (cause) {
    throw new RedemptionFailed('lab-api unreachable', 503);
  }

  if (response.status === 404) {
    throw new RedemptionFailed('reference is not redeemable', 404);
  }
  if (!response.ok) {
    throw new RedemptionFailed('lab-api refused the redemption', 502);
  }

  const body = await response.json();
  if (!body || !body.parameters || !body.parameters.hostname) {
    throw new RedemptionFailed('redemption returned no usable target', 502);
  }
  return body;
}

module.exports = { redeemDesktopAccess, RedemptionFailed };
