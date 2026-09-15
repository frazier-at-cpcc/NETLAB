import asyncio
import inspect
import logging
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from xml.etree import ElementTree

import httpx
from oauthlib.oauth1 import Client

logger = logging.getLogger(__name__)

_POX_NAMESPACE = "http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0"
POLL_INTERVAL_SECONDS = 5.0

_CONSUMER_SECRET_ENV = {
    "cpcc-canvas": "LTI11_CANVAS_SECRET",
    "cpcc-blackboard": "LTI11_BLACKBOARD_SECRET",
    "cpcc-moodle": "LTI11_MOODLE_SECRET",
    "cpcc-brightspace": "LTI11_BRIGHTSPACE_SECRET",
}

CLAIM_DUE_SQL = """
SELECT
    d.id,
    d.event_id,
    d.cell_id,
    d.attempts,
    e.score_raw,
    e.score_max,
    c.sourcedid,
    c.outcome_service_url,
    c.consumer_key
FROM grade_deliveries d
JOIN grade_events e ON e.id = d.event_id
JOIN grade_cells c ON c.id = d.cell_id
WHERE d.state IN ('PENDING', 'RETRYING')
  AND d.next_attempt_at <= $1
ORDER BY d.next_attempt_at, d.id
LIMIT 1
FOR UPDATE OF d SKIP LOCKED
"""

UPDATE_DELIVERED_SQL = """
UPDATE grade_deliveries
   SET state = 'DELIVERED',
       attempts = $2,
       delivered_at = $3,
       last_error = NULL
 WHERE id = $1
"""

UPDATE_RETRYING_SQL = """
UPDATE grade_deliveries
   SET state = 'RETRYING',
       attempts = $2,
       next_attempt_at = $3,
       last_error = $4
 WHERE id = $1
"""

UPDATE_DEAD_LETTER_SQL = """
UPDATE grade_deliveries
   SET state = 'DEAD_LETTER',
       attempts = $2,
       last_error = $3
 WHERE id = $1
"""


def scale_score(score_raw, score_max) -> Decimal:
    raw = Decimal(str(score_raw))
    maximum = Decimal(str(score_max))
    if maximum <= 0:
        ratio = Decimal("0")
    else:
        ratio = raw / maximum
    if ratio < 0:
        ratio = Decimal("0")
    elif ratio > 1:
        ratio = Decimal("1")
    return ratio.quantize(Decimal("0.0001"))


def build_replace_result(sourcedid: str, score: Decimal) -> str:
    envelope = ElementTree.Element(f"{{{_POX_NAMESPACE}}}imsx_POXEnvelopeRequest")
    header = ElementTree.SubElement(envelope, f"{{{_POX_NAMESPACE}}}imsx_POXHeader")
    info = ElementTree.SubElement(header, f"{{{_POX_NAMESPACE}}}imsx_POXRequestHeaderInfo")
    ElementTree.SubElement(info, f"{{{_POX_NAMESPACE}}}imsx_version").text = "V1.0"
    ElementTree.SubElement(info, f"{{{_POX_NAMESPACE}}}imsx_messageIdentifier").text = uuid.uuid4().hex
    body = ElementTree.SubElement(envelope, f"{{{_POX_NAMESPACE}}}imsx_POXBody")
    request = ElementTree.SubElement(body, f"{{{_POX_NAMESPACE}}}replaceResultRequest")
    record = ElementTree.SubElement(request, f"{{{_POX_NAMESPACE}}}resultRecord")
    guid = ElementTree.SubElement(record, f"{{{_POX_NAMESPACE}}}sourcedGUID")
    ElementTree.SubElement(guid, f"{{{_POX_NAMESPACE}}}sourcedId").text = sourcedid
    result = ElementTree.SubElement(record, f"{{{_POX_NAMESPACE}}}result")
    score_node = ElementTree.SubElement(result, f"{{{_POX_NAMESPACE}}}resultScore")
    ElementTree.SubElement(score_node, f"{{{_POX_NAMESPACE}}}language").text = "en"
    ElementTree.SubElement(score_node, f"{{{_POX_NAMESPACE}}}textString").text = str(score)
    ElementTree.register_namespace("", _POX_NAMESPACE)
    return ElementTree.tostring(envelope, encoding="utf-8", xml_declaration=True).decode("utf-8")


def pox_status(body: str) -> str:
    """Return the imsx_codeMajor value, or 'malformed' when there is none."""
    if not (body or "").strip():
        return "malformed"
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return "malformed"
    node = next(
        (n for n in root.iter() if n.tag.rsplit("}", 1)[-1] == "imsx_codeMajor"),
        None,
    )
    if node is None:
        return "malformed"
    return (node.text or "").strip().lower() or "malformed"


def load_lti11_secrets(environ=None) -> dict[str, str]:
    env = os.environ if environ is None else environ
    secrets = {}
    for consumer_key, env_name in _CONSUMER_SECRET_ENV.items():
        value = env.get(env_name)
        if value:
            secrets[consumer_key] = value
    test_secret = env.get("LTI11_TEST_SECRET", "test-secret-dev-only")
    if test_secret:
        secrets["test-consumer"] = test_secret
    return secrets


def _backoff_seconds(attempts: int, rng) -> float:
    return min(60 * (2 ** (attempts - 1)), 3600) + rng.uniform(0, 5)


def _sign(consumer_key: str, secret: str, url: str, body: str) -> dict:
    client = Client(consumer_key, client_secret=secret, signature_type="AUTH_HEADER")
    _, headers, _ = client.sign(
        url,
        http_method="POST",
        body=body,
        headers={"Content-Type": "application/xml"},
    )
    headers = dict(headers)
    headers["Content-Type"] = "application/xml"
    return headers


async def _post(http, url: str, **kwargs):
    result = http.post(url, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    return result


def _log_result(delivery_id, event_id, cell_id, state) -> None:
    logger.info(
        "POX delivery %s event %s cell %s -> %s",
        delivery_id,
        event_id,
        cell_id,
        state,
    )


async def _finish(conn, http, secrets, now, row, rng) -> None:
    delivery_id = row["id"]
    event_id = row["event_id"]
    cell_id = row["cell_id"]
    attempts = int(row["attempts"]) + 1
    secret = None
    if secrets:
        secret = secrets.get(row["consumer_key"])
    if not secret:
        await conn.execute(UPDATE_DEAD_LETTER_SQL, delivery_id, attempts, "missing consumer secret")
        _log_result(delivery_id, event_id, cell_id, "DEAD_LETTER")
        return

    body = build_replace_result(row["sourcedid"], scale_score(row["score_raw"], row["score_max"]))
    try:
        headers = _sign(row["consumer_key"], secret, row["outcome_service_url"], body)
        response = await _post(
            http,
            row["outcome_service_url"],
            content=body,
            headers=headers,
        )
    except httpx.RequestError:
        delay = _backoff_seconds(attempts, rng)
        next_at = now + timedelta(seconds=delay)
        await conn.execute(
            UPDATE_RETRYING_SQL,
            delivery_id,
            attempts,
            next_at,
            "upstream request failed",
        )
        _log_result(delivery_id, event_id, cell_id, "RETRYING")
        return

    status = response.status_code
    if 200 <= status < 300:
        code = pox_status(getattr(response, "text", "") or "")
        if code == "success":
            await conn.execute(UPDATE_DELIVERED_SQL, delivery_id, attempts, now)
            _log_result(delivery_id, event_id, cell_id, "DELIVERED")
            return
        if code in ("processing", "malformed"):
            delay = _backoff_seconds(attempts, rng)
            await conn.execute(
                UPDATE_RETRYING_SQL,
                delivery_id,
                attempts,
                now + timedelta(seconds=delay),
                f"upstream POX status {code}",
            )
            _log_result(delivery_id, event_id, cell_id, "RETRYING")
            return
        await conn.execute(
            UPDATE_DEAD_LETTER_SQL,
            delivery_id,
            attempts,
            f"upstream rejected the score: {code}",
        )
        _log_result(delivery_id, event_id, cell_id, "DEAD_LETTER")
        return
    if 400 <= status < 500:
        await conn.execute(
            UPDATE_DEAD_LETTER_SQL,
            delivery_id,
            attempts,
            f"upstream returned HTTP {status}",
        )
        _log_result(delivery_id, event_id, cell_id, "DEAD_LETTER")
        return

    delay = _backoff_seconds(attempts, rng)
    next_at = now + timedelta(seconds=delay)
    await conn.execute(
        UPDATE_RETRYING_SQL,
        delivery_id,
        attempts,
        next_at,
        f"upstream returned HTTP {status}",
    )
    _log_result(delivery_id, event_id, cell_id, "RETRYING")


async def deliver_due(db, http, secrets, now, *, rng=random):
    processed = 0
    while True:
        async with db.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(CLAIM_DUE_SQL, now)
                if row is None:
                    return processed
                await _finish(conn, http, secrets, now, row, rng)
                processed += 1


async def pox_delivery_loop(db, *, interval=POLL_INTERVAL_SECONDS, http=None, secrets=None):
    close_http = False
    if http is None:
        http = httpx.AsyncClient(timeout=10.0)
        close_http = True
    if secrets is None:
        secrets = load_lti11_secrets()
    try:
        while True:
            try:
                await deliver_due(db, http, secrets, datetime.now(timezone.utc))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("POX delivery loop error")
            await asyncio.sleep(interval)
    finally:
        if close_http:
            await http.aclose()
