"""Grade backfill from the Learning Record Store.

Email is reintroduced as a lookup key here, and only here, and only for
statements the store accepted before a configured cutover. See the spec.
"""


def candidate_mboxes(email: str, domains: list[str]) -> list[str]:
    """Return the launch address plus the same local part at each configured domain.

    Substitution is by whole domain. A local part is never matched on its own,
    because a different institution shares this store and a collision would move
    a grade between colleges.
    """
    address = (email or "").strip()
    if address.count("@") != 1:
        return []
    local, _, domain = address.partition("@")
    if not local or not domain:
        return []
    ordered = [address]
    if domain in domains:
        for candidate_domain in domains:
            candidate = f"{local}@{candidate_domain}"
            if candidate not in ordered:
                ordered.append(candidate)
    return [f"mailto:{a}" for a in ordered]


def best_statement(statements: list[dict]) -> dict | None:
    """Return the statement with the highest scaled score, or None."""
    best = None
    best_score = None
    for statement in statements or []:
        scaled = ((statement.get("result") or {}).get("score") or {}).get("scaled")
        if scaled is None:
            continue
        if best_score is None or scaled > best_score:
            best, best_score = statement, scaled
    return best
