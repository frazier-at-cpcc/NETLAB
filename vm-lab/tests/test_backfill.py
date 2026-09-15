from api.backfill import candidate_mboxes, best_statement

DOMAINS = ["email.cpcc.edu", "lab.cpcc.edu", "email.edu.cpcc", "cpcc.email.edu", "cpcc.edu"]

def test_candidates_cover_every_configured_domain():
    got = candidate_mboxes("augarte0@email.cpcc.edu", DOMAINS)
    assert "mailto:augarte0@email.cpcc.edu" in got
    assert "mailto:augarte0@lab.cpcc.edu" in got
    assert "mailto:augarte0@email.edu.cpcc" in got
    assert len(got) == len(set(got))

def test_an_unlisted_domain_is_never_substituted():
    got = candidate_mboxes("student@lancers.lenoircc.edu", DOMAINS)
    assert got == ["mailto:student@lancers.lenoircc.edu"]

def test_an_empty_or_malformed_address_yields_nothing():
    assert candidate_mboxes("", DOMAINS) == []
    assert candidate_mboxes("notanemail", DOMAINS) == []

def test_best_statement_picks_the_highest_scaled_score():
    low = {"id": "a", "result": {"score": {"scaled": 0.4}}}
    high = {"id": "b", "result": {"score": {"scaled": 0.9}}}
    assert best_statement([low, high])["id"] == "b"

def test_best_statement_of_nothing_is_none():
    assert best_statement([]) is None
