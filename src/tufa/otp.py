"""
Implementations of HOTP and TOTP algorithms.

https://www.ietf.org/rfc/rfc4226.txt
https://www.ietf.org/rfc/rfc6238.txt
"""

import base64
import hmac
import struct
import time


def decode_secret(secret):
    """Decode a base32-encoded secret to bytes."""
    return base64.b32decode(secret + '=' * (-len(secret) % 8))


def get_hotp(secret, counter, algorithm=None, digits=None):
    """
    Generate an HOTP from the given parameters.
    :param secret: Secret as a base32-encoded string
    :param counter: Counter value
    :param algorithm: Digest algorithm to use
    :param digits: Number of OTP digits to generate
    """
    algorithm = algorithm or 'SHA1'
    digits = digits or 6
    secret_bytes = decode_secret(secret)
    counter_bytes = struct.pack('>q', counter)
    hmac_bytes = hmac.digest(secret_bytes, counter_bytes, algorithm)
    # Use last byte, not 19th byte as specified in RFC-4226
    # https://www.rfc-editor.org/errata/eid6756
    offset = hmac_bytes[-1] & 0xf
    dbc, = struct.unpack_from('>L', hmac_bytes, offset)
    dbc &= 0x7FFFFFFF
    return str(dbc)[-digits:].zfill(digits)


def get_totp(secret, period=None, algorithm=None, digits=None):
    """Generate a TOTP with the given parameters at the current time."""
    period = period or 30
    counter = int(time.time() / period)
    return get_hotp(secret, counter, algorithm=algorithm, digits=digits)
