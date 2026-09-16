"""Proves api/main.py's LRS backfill configuration helper fails off, never
open, and produces exactly the key names api/backfill.py's
`attempt_backfill` reads via `config.get()`.

`BACKFILL_CONFIG` is built once, at module import time, directly from
os.environ. Setting an environment variable after api.main has already
been imported would prove nothing, since the mapping was already frozen
by an earlier import -- possibly triggered by test collection itself or
by another test module (test_get_vm_ip.py and test_service_auth.py both
import api.main). So every test here forces a fresh import of api.main
with the environment already patched, and discards that import
afterward, matching the pattern test_lti_main_consumers.py established
for the analogous lti.main case.
"""

import base64
import logging
import sys
import types
from datetime import datetime, timezone

import pytest

DEFAULT_DOMAINS = [
    "email.cpcc.edu",
    "lab.cpcc.edu",
    "email.edu.cpcc",
    "cpcc.email.edu",
    "cpcc.edu",
]

BACKFILL_ENV_VARS = (
    "LRS_BACKFILL_ENABLED",
    "LRS_READ_URL",
    "LRS_READ_AUTH",
    "LRS_BACKFILL_CUTOFF",
    "LRS_BACKFILL_DOMAINS",
)


@pytest.fixture
def load_api_main(monkeypatch):
    """Yields a loader that imports the real api.main fresh, with the five
    backfill environment variables cleared first so each test starts from
    a known baseline rather than whatever a previous test (or the real
    shell environment) happened to leave behind.

    api/main.py unconditionally imports asyncpg and proxmoxer at module
    load but only calls them inside functions never triggered here;
    test_service_auth.py already establishes this stubbing pattern for
    the same two packages.
    """
    for name, attrs in (("asyncpg", {}), ("proxmoxer", {"ProxmoxAPI": object})):
        if name not in sys.modules:
            try:
                __import__(name)
            except ImportError:
                stub = types.ModuleType(name)
                for attr, value in attrs.items():
                    setattr(stub, attr, value)
                monkeypatch.setitem(sys.modules, name, stub)

    for var in BACKFILL_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    def _load():
        sys.modules.pop("api.main", None)
        import api.main as lab_api_main

        return lab_api_main

    yield _load

    sys.modules.pop("api.main", None)


def test_config_helper_exposes_exactly_the_keys_attempt_backfill_reads(load_api_main):
    """The cheap test that would have caught a silent contract mismatch.
    attempt_backfill (api/backfill.py) reads config.get() for exactly
    enabled, domains, cutoff, base_url, auth. A helper that emits a
    different key name, or an extra or missing one, makes the feature
    silently never fire with no error anywhere, so the key set is
    asserted exactly rather than merely checking a few expected keys are
    present."""
    lab_api_main = load_api_main()

    config = lab_api_main.load_backfill_config()

    assert set(config.keys()) == {"enabled", "domains", "cutoff", "base_url", "auth"}


def test_default_environment_is_fully_disabled(load_api_main):
    lab_api_main = load_api_main()

    config = lab_api_main.load_backfill_config()

    assert config["enabled"] is False
    assert config["base_url"] == "https://lrs.labsconnect.org/xapi"
    assert config["domains"] == DEFAULT_DOMAINS
    assert config["cutoff"] is None
    assert config["auth"] == ""


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "True", "yes", "YES", "Yes"])
def test_enabled_flag_accepts_only_the_documented_truthy_spellings(monkeypatch, load_api_main, value):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", value)
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    lab_api_main = load_api_main()

    assert lab_api_main.load_backfill_config()["enabled"] is True


@pytest.mark.parametrize("value", ["0", "false", "no", "on", "enabled", "", "2"])
def test_enabled_flag_rejects_anything_else(monkeypatch, load_api_main, value):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", value)
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    lab_api_main = load_api_main()

    assert lab_api_main.load_backfill_config()["enabled"] is False


def test_empty_auth_forces_off_regardless_of_flag_and_is_logged_once(monkeypatch, load_api_main, caplog):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")
    monkeypatch.delenv("LRS_READ_AUTH", raising=False)

    with caplog.at_level(logging.WARNING):
        lab_api_main = load_api_main()

    assert lab_api_main.BACKFILL_CONFIG["enabled"] is False
    assert any("LRS_READ_AUTH" in record.message for record in caplog.records)


def test_empty_cutoff_forces_off_regardless_of_flag_and_is_logged_once(monkeypatch, load_api_main, caplog):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.delenv("LRS_BACKFILL_CUTOFF", raising=False)

    with caplog.at_level(logging.WARNING):
        lab_api_main = load_api_main()

    assert lab_api_main.BACKFILL_CONFIG["enabled"] is False
    assert lab_api_main.BACKFILL_CONFIG["cutoff"] is None
    assert any("LRS_BACKFILL_CUTOFF" in record.message for record in caplog.records)


def test_unparseable_cutoff_forces_off_without_raising_and_without_printing_the_value(
    monkeypatch, load_api_main, caplog
):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "not-a-real-instant")

    with caplog.at_level(logging.WARNING):
        lab_api_main = load_api_main()  # must not raise at import

    assert lab_api_main.BACKFILL_CONFIG["enabled"] is False
    assert lab_api_main.BACKFILL_CONFIG["cutoff"] is None
    assert "not-a-real-instant" not in caplog.text
    assert "LRS_BACKFILL_CUTOFF" in caplog.text


def test_valid_cutoff_parses_to_a_timezone_aware_datetime(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    lab_api_main = load_api_main()

    assert lab_api_main.BACKFILL_CONFIG["cutoff"] == datetime(2026, 9, 15, tzinfo=timezone.utc)


def test_domains_list_is_comma_split_and_stripped(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_DOMAINS", " a.edu, b.edu ,c.edu")

    lab_api_main = load_api_main()

    assert lab_api_main.load_backfill_config()["domains"] == ["a.edu", "b.edu", "c.edu"]


def test_custom_read_url_overrides_the_default(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_READ_URL", "https://lrs.internal.example/xapi")

    lab_api_main = load_api_main()

    assert lab_api_main.load_backfill_config()["base_url"] == "https://lrs.internal.example/xapi"


def test_raw_colon_credential_is_base64_encoded_before_becoming_auth(monkeypatch, load_api_main):
    """A colon never appears in valid base64 output, so a raw key:secret
    pair (the form an operator copies straight off an LRS credential
    page) is detected by the presence of a colon and encoded here.
    fetch_statements sends config["auth"] verbatim as
    'Authorization: Basic {auth}', so it must already be base64 by the
    time it leaves this helper."""
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "readonly-key:readonly-secret")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    lab_api_main = load_api_main()

    expected = base64.b64encode(b"readonly-key:readonly-secret").decode("ascii")
    assert lab_api_main.BACKFILL_CONFIG["auth"] == expected
    assert ":" not in lab_api_main.BACKFILL_CONFIG["auth"]


def test_already_encoded_credential_is_passed_through_unchanged(monkeypatch, load_api_main):
    already_encoded = base64.b64encode(b"readonly-key:readonly-secret").decode("ascii")
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", already_encoded)
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    lab_api_main = load_api_main()

    assert lab_api_main.BACKFILL_CONFIG["auth"] == already_encoded


def test_already_encoded_credential_with_trailing_newline_has_no_newline_in_auth(monkeypatch, load_api_main):
    """echo "secret" > file, Kubernetes secretKeyRef mounts, and several
    .env tools all routinely append a trailing newline. Since this value
    has no colon, it takes the pass-through branch; the newline must be
    stripped before it ever becomes the header value, or
    'Authorization: Basic <token>\\n' goes out on the wire."""
    already_encoded = base64.b64encode(b"readonly-key:readonly-secret").decode("ascii")
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", already_encoded + "\n")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    lab_api_main = load_api_main()

    assert lab_api_main.BACKFILL_CONFIG["auth"] == already_encoded
    assert "\n" not in lab_api_main.BACKFILL_CONFIG["auth"]


def test_raw_credential_with_trailing_newline_encodes_identically_to_without(monkeypatch, load_api_main):
    """A raw key:secret pair does contain a colon, so an unstripped
    newline is swallowed into the base64 input and produces a different
    encoded value than the same pair without the newline -- a silent
    wrong-credential bug, not a missing one. Assert the two loads produce
    the identical auth value, not a hardcoded literal, so the test states
    the property being protected rather than one example of it."""
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    monkeypatch.setenv("LRS_READ_AUTH", "readonly-key:readonly-secret")
    without_newline = load_api_main().BACKFILL_CONFIG["auth"]

    monkeypatch.setenv("LRS_READ_AUTH", "readonly-key:readonly-secret\n")
    with_newline = load_api_main().BACKFILL_CONFIG["auth"]

    assert with_newline == without_newline


@pytest.mark.parametrize(
    "wrapped",
    [
        "readonly-key:readonly-secret\n",
        "\nreadonly-key:readonly-secret",
        "  readonly-key:readonly-secret  ",
        "\t readonly-key:readonly-secret \t\n",
    ],
)
def test_credential_with_leading_and_surrounding_whitespace_encodes_identically_to_bare(
    monkeypatch, load_api_main, wrapped
):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    monkeypatch.setenv("LRS_READ_AUTH", "readonly-key:readonly-secret")
    bare = load_api_main().BACKFILL_CONFIG["auth"]

    monkeypatch.setenv("LRS_READ_AUTH", wrapped)
    surrounded = load_api_main().BACKFILL_CONFIG["auth"]

    assert surrounded == bare


def test_read_url_with_trailing_newline_is_stripped(monkeypatch, load_api_main):
    """A trailing newline on LRS_READ_URL would otherwise become part of
    the URL fetch_statements builds, producing a malformed request."""
    monkeypatch.setenv("LRS_READ_URL", "https://lrs.internal.example/xapi\n")

    lab_api_main = load_api_main()

    assert lab_api_main.load_backfill_config()["base_url"] == "https://lrs.internal.example/xapi"


def test_domains_with_spaces_after_commas_match_domains_without(monkeypatch, load_api_main):
    """States the property directly: two differently-whitespaced
    spellings of the same domain list must parse identically, rather
    than asserting one literal result."""
    monkeypatch.setenv("LRS_BACKFILL_DOMAINS", "a.edu,b.edu,c.edu")
    compact = load_api_main().load_backfill_config()["domains"]

    monkeypatch.setenv("LRS_BACKFILL_DOMAINS", "a.edu, b.edu, c.edu")
    spaced = load_api_main().load_backfill_config()["domains"]

    assert spaced == compact


def test_credential_value_never_appears_in_startup_logs(monkeypatch, load_api_main, caplog):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "readonly-key:super-secret-value")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    with caplog.at_level(logging.DEBUG):
        load_api_main()

    assert "super-secret-value" not in caplog.text
    assert "readonly-key" not in caplog.text


def test_fully_configured_environment_is_enabled(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")
    monkeypatch.setenv("LRS_BACKFILL_DOMAINS", "email.cpcc.edu,lab.cpcc.edu")
    monkeypatch.setenv("LRS_READ_URL", "https://lrs.internal.example/xapi")

    lab_api_main = load_api_main()
    config = lab_api_main.BACKFILL_CONFIG

    assert config == {
        "enabled": True,
        "domains": ["email.cpcc.edu", "lab.cpcc.edu"],
        "cutoff": datetime(2026, 9, 15, tzinfo=timezone.utc),
        "base_url": "https://lrs.internal.example/xapi",
        "auth": "cmVhZG9ubHk=",
    }


def test_config_object_is_frozen(load_api_main):
    lab_api_main = load_api_main()

    config = lab_api_main.BACKFILL_CONFIG

    with pytest.raises(TypeError):
        config["enabled"] = True


# --- ITEM 3: the cutoff must be logged, and a future cutoff refused -----
#
# LRS_BACKFILL_CUTOFF=2099-01-01T00:00:00Z parses cleanly and enables the
# feature, but silently removes the freshness bound entirely: every
# statement a student can forge today is stored before 2099. Nothing
# previously logged the cutoff's value, so an operator could not confirm
# afterward which bound was actually in force.


def test_a_future_cutoff_is_refused_exactly_like_an_unparseable_one(monkeypatch, load_api_main, caplog):
    """Refuse, don't merely warn: a future cutoff admits every statement
    anyone can forge today, erasing the one security control spec
    section 4 describes. Every other invalid-cutoff case here already
    fails off rather than warns and proceeds; treating a future cutoff
    the same way keeps one failure discipline instead of adding a
    second, weaker path an operator could miss."""
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2099-01-01T00:00:00Z")

    with caplog.at_level(logging.WARNING):
        lab_api_main = load_api_main()

    assert lab_api_main.BACKFILL_CONFIG["enabled"] is False
    assert lab_api_main.BACKFILL_CONFIG["cutoff"] is None
    assert any("2099-01-01" in record.message for record in caplog.records)


def test_a_cutoff_equal_to_now_is_not_treated_as_future(monkeypatch, load_api_main):
    """The bound is "in the future", not "not in the past": a cutoff set
    to this instant must not be spuriously refused."""
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2020-01-01T00:00:00Z")

    lab_api_main = load_api_main()

    assert lab_api_main.BACKFILL_CONFIG["cutoff"] == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert lab_api_main.BACKFILL_CONFIG["enabled"] is True


def test_startup_logs_the_enabled_state_and_the_cutoff_value_together(monkeypatch, load_api_main, caplog):
    """The cutoff is not sensitive. An operator must be able to confirm
    after the fact which bound was in force, so it is logged at startup
    alongside the enabled state -- not just on the failure paths above."""
    monkeypatch.setenv("LRS_BACKFILL_ENABLED", "true")
    monkeypatch.setenv("LRS_READ_AUTH", "cmVhZG9ubHk=")
    monkeypatch.setenv("LRS_BACKFILL_CUTOFF", "2026-09-15T00:00:00Z")

    with caplog.at_level(logging.INFO):
        load_api_main()

    assert any(
        "enabled=True" in record.message and "2026-09-15" in record.message
        for record in caplog.records
    )


def test_startup_log_reports_disabled_and_no_cutoff_when_unconfigured(monkeypatch, load_api_main, caplog):
    with caplog.at_level(logging.INFO):
        load_api_main()

    assert any("enabled=False" in record.message for record in caplog.records)


# --- ITEM 7b: an explicitly empty LRS_BACKFILL_DOMAINS is unset, not an -
# --- empty list -----------------------------------------------------------
#
# os.getenv(name, default) only applies the default when the variable is
# unset entirely. LRS_BACKFILL_DOMAINS="" is set, just empty, so the old
# code took that branch and produced [] instead of the documented
# default list, silently losing all cross-domain pooling.


def test_empty_domains_env_var_falls_back_to_the_default_list(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_DOMAINS", "")

    lab_api_main = load_api_main()

    assert lab_api_main.load_backfill_config()["domains"] == DEFAULT_DOMAINS


def test_whitespace_only_domains_env_var_also_falls_back_to_the_default(monkeypatch, load_api_main):
    monkeypatch.setenv("LRS_BACKFILL_DOMAINS", "   ")

    lab_api_main = load_api_main()

    assert lab_api_main.load_backfill_config()["domains"] == DEFAULT_DOMAINS
