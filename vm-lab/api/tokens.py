import hashlib
import secrets


def mint_grade_token() -> str:
    return secrets.token_urlsafe(32)


def hash_grade_token(token: str) -> str:
    if not token:
        raise ValueError("grade token is empty")
    return hashlib.sha256(token.encode("ascii")).hexdigest()
