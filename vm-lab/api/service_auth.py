import hmac
import os

SERVICE_TOKEN_HEADER = "X-LabsConnect-Service-Token"


class ServiceTokenError(Exception):
    """Raised when a service-to-service call is not authorised."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def check_service_token(*, configured: str, presented: str | None) -> None:
    """Fail closed. An unset token refuses every caller rather than admitting all."""
    if not configured:
        raise ServiceTokenError(503, "service token is not configured")
    if not presented or not hmac.compare_digest(presented, configured):
        raise ServiceTokenError(403, "service token required")


def service_token() -> str:
    return os.getenv("LAB_API_SERVICE_TOKEN", "")


def service_headers() -> dict[str, str]:
    token = service_token()
    return {SERVICE_TOKEN_HEADER: token} if token else {}
