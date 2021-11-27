"""Input validation."""

import binascii
import string

from .exceptions import ValidationError
from .otp import decode_secret


def validate_type(type_):
    """Validate OTP type parameter."""
    if type_ not in ('totp', 'hotp'):
        raise ValidationError("Type must be one of: totp, hotp")
    return type_


def validate_secret(secret):
    """Validate and normalize a base32 secret from user input."""
    trans = str.maketrans(string.ascii_lowercase, string.ascii_uppercase,
                          '- =')
    secret = secret.translate(trans)
    if not secret:
        raise ValidationError("Secret must be a valid base32-encoded string")
    try:
        decode_secret(secret)
    except (binascii.Error, ValueError) as e:
        raise ValidationError("Secret must be a valid base32-encoded string") \
             from e
    return secret


def validate_algorithm(algorithm):
    """Validate algorithm parameter."""
    if algorithm is None:
        return None
    if algorithm not in ('SHA1', 'SHA256', 'SHA512'):
        raise ValidationError("Algorithm must be one of: SHA1, SHA256, SHA512")
    return algorithm


def validate_digits(digits):
    """Validate digits parameter."""
    if digits is None:
        return None
    try:
        digits = int(digits)
    except ValueError as e:
        raise ValidationError("Digits must be a valid integer value") from e
    if digits < 6 or digits > 8:
        raise ValidationError("Digits must be between 6 and 8, inclusive")
    return digits


def validate_counter(counter):
    """Validate counter parameter."""
    try:
        counter = int(counter)
    except ValueError as e:
        raise ValidationError("Counter must be a valid integer value") from e
    return counter


def validate_period(period):
    """Validate period parameter."""
    if period is None:
        return None
    try:
        period = int(period)
    except ValueError as e:
        raise ValidationError("Period must be a valid integer value") from e
    if period <= 0:
        raise ValidationError("Period must be greater than 0")
    return period
