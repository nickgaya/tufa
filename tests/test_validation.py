"""Tests of tufa.validation."""

import pytest

from tufa import validation
from tufa.exceptions import ValidationError


@pytest.mark.parametrize(('type_'), ['totp', 'hotp'])
def test_validate_type(type_):
    assert validation.validate_type(type_) == type_


@pytest.mark.parametrize('type_', ['', 'bad'])
def test_validate_type_invalid(type_):
    with pytest.raises(ValidationError):
        validation.validate_type(type_)


@pytest.mark.parametrize(('secret', 'expected'), [
    ('ME======', 'ME'),
    ('MFRA====', 'MFRA'),
    ('MFRGG===', 'MFRGG'),
    ('MFRGGZA=', 'MFRGGZA'),
    ('MFRGGZDF', 'MFRGGZDF'),
    ('abcdefgh', 'ABCDEFGH'),
    ('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
    ('6G2N OZLG 3ACC UFM2 7Q7P ZDZ3 EYNJ 7RNY NOLU 3QB3 5CEP DRUO 6EP6',
     '6G2NOZLG3ACCUFM27Q7PZDZ3EYNJ7RNYNOLU3QB35CEPDRUO6EP6'),
    ('252F-656H-R47W-HAOG', '252F656HR47WHAOG'),
])
def test_validate_secret(secret, expected):
    assert validation.validate_secret(secret) == expected


@pytest.mark.parametrize('secret', [
    '',
    ' ',
    '========',
    'A',
    'ABC',
    'ABCDEF',
    'ABCDEF10',
    'André',
])
def test_validate_secret_invalid(secret):
    with pytest.raises(ValidationError):
        validation.validate_secret(secret)


@pytest.mark.parametrize('algorithm', [None, 'SHA1', 'SHA256', 'SHA512'])
def test_validate_algorithm(algorithm):
    assert validation.validate_algorithm(algorithm) == algorithm


@pytest.mark.parametrize('algorithm', ['', 'bad'])
def test_validate_algorithm_invalid(algorithm):
    with pytest.raises(ValidationError):
        validation.validate_algorithm(algorithm)


@pytest.mark.parametrize(('digits', 'expected'), [
    (None, None),
    (6, 6),
    ('7', 7),
    (8, 8),
])
def test_validate_digits(digits, expected):
    assert validation.validate_digits(digits) == expected


@pytest.mark.parametrize('digits', ['', 5, '9', 'abcd'])
def test_validate_digits_invalid(digits):
    with pytest.raises(ValidationError):
        validation.validate_digits(digits)


@pytest.mark.parametrize(('counter', 'expected'), [
    (0, 0),
    (-5, -5),
    (10, 10),
    ('42', 42),
])
def test_validate_counter(counter, expected):
    assert validation.validate_counter(counter) == expected


@pytest.mark.parametrize('counter', ['', 'abcd'])
def test_validate_counter_invalid(counter):
    with pytest.raises(ValidationError):
        validation.validate_counter(counter)


@pytest.mark.parametrize(('period', 'expected'), [
    (None, None),
    (15, 15),
    ('30', 30),
])
def test_validate_period(period, expected):
    assert validation.validate_period(period) == expected


@pytest.mark.parametrize('period', ['', 0, -1, '-20', 'abcd'])
def test_validate_period_invalid(period):
    with pytest.raises(ValidationError):
        validation.validate_period(period)
