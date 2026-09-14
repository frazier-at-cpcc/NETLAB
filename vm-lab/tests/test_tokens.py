from api.tokens import hash_grade_token, mint_grade_token


def test_mint_grade_token_is_urlsafe_and_unique():
    a = mint_grade_token()
    b = mint_grade_token()
    assert a != b
    assert len(a) >= 32
    assert "/" not in a


def test_hash_grade_token_is_sha256_hex():
    import hashlib
    digest = hash_grade_token("unit-test-token")
    assert digest == hashlib.sha256(b"unit-test-token").hexdigest()
    assert digest != "unit-test-token"
