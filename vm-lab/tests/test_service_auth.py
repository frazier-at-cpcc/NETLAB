import pytest

from api.service_auth import ServiceTokenError, check_service_token


def test_absent_configuration_refuses_every_caller():
    with pytest.raises(ServiceTokenError) as exc:
        check_service_token(configured="", presented="anything")
    assert exc.value.status_code == 503


def test_wrong_token_is_refused():
    with pytest.raises(ServiceTokenError) as exc:
        check_service_token(configured="right", presented="wrong")
    assert exc.value.status_code == 403


def test_missing_token_is_refused():
    with pytest.raises(ServiceTokenError) as exc:
        check_service_token(configured="right", presented=None)
    assert exc.value.status_code == 403


def test_matching_token_is_accepted():
    check_service_token(configured="right", presented="right")
