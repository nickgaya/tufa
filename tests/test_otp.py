"""Tests of tufa.otp functions."""

import pytest

from tufa.otp import get_hotp, get_totp

SECRET = 'TLPXMFSTNRIPZ6Z6'
TIME = 1638067104.882953


def _dict_id_func(param):
    if isinstance(param, dict):
        return '-'.join(f'{key}={value}' for key, value in param.items())
    return repr(param)


@pytest.fixture
def mock_time(mocker):
    mock_time = mocker.patch('tufa.otp.time', autospec=True)
    mock_time.time.return_value = TIME
    return mock_time


@pytest.mark.parametrize(('counter', 'kwargs', 'otp'), [
    (0, {}, '654107'),
    (1, {}, '041379'),
    (100, {}, '926002'),
    (-10, {}, '102902'),
    (123, {'algorithm': 'SHA256'}, '138176'),
    (456, {'algorithm': 'SHA512'}, '240689'),
    (0, {'digits': 8}, '73654107'),
], ids=_dict_id_func)
def test_get_hotp(counter, kwargs, otp):
    assert get_hotp(SECRET, counter, **kwargs) == otp


@pytest.mark.usefixtures('mock_time')
@pytest.mark.parametrize(('kwargs', 'otp'), [
    ({}, '724001'),
    ({'period': 15}, '868640'),
    ({'period': 60}, '111068'),
    ({'algorithm': 'SHA256'}, '864433'),
    ({'algorithm': 'SHA512'}, '668385'),
    ({'digits': 8}, '31724001'),
], ids=_dict_id_func)
def test_get_totp(kwargs, otp):
    assert get_totp(SECRET, **kwargs) == otp
