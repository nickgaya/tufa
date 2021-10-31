import base64
import binascii
import getpass
import hmac
import logging
import os
import sqlite3
import string
import struct
import subprocess
import sys
import time
from argparse import ArgumentParser

logger = logging.getLogger('twofa')


### Exceptions

class TwofaError(Exception):
    """Base exception type for this script."""


class KeychainError(TwofaError):
    """"Exception type for errors interacting with Mac OS keychain."""


class UserError(TwofaError):
    """Exception type used to indicate user error."""


class CredentialExistsError(UserError):
    """Exception type when the user attempts to add an existing credential."""


class ValidationError(UserError):
    """Exception type used to indicate invalid user input."""


### OTP generation

def get_otp(secret, value, algorithm=None, digits=None):
    """
    Generate an OTP from the given parameters.
    :param secret: Secret as a base32-encoded string
    :param value: Counter value
    :param algorithm: Digest algorithm to use
    :param digits: Number of OTP digits to generate
    """
    algorithm = algorithm or 'SHA1'
    digits = digits or 6
    secret_bytes = base64.b32decode(secret)
    counter_bytes = struct.pack('>q', value)
    hmac_bytes = hmac.digest(secret_bytes, counter_bytes, algorithm)
    offset = hmac_bytes[19] & 0xf
    dbc, = struct.unpack_from('>L', hmac_bytes, offset)
    dbc &= 0x7FFFFFFF
    return str(dbc)[-digits:].zfill(digits)


def get_totp(secret, period=None, algorithm=None, digits=None):
    """Generate a TOTP with the given parameters at the current time."""
    period = period or 30
    value = int(time.time() / period)
    return get_otp(secret, value, algorithm=algorithm, digits=digits)


### Persistence layer

class SecretStore:
    """Class for storing and retrieving secrets in the Mac OS keychain."""

    def store_secret(self, name, secret, keychain=None, update=False):
        """Store a secret for the given credential name."""
        command = ['security', 'add-generic-password',
                   # The service and account parameters together uniquely
                   # identify a keychain item
                   '-s', 'twofa', '-a', name,
                   # Additional display parameters shown in Keychain Access
                   '-l', f'twofa: {name}',
                   '-D', 'hotp/totp secret',
                   # XXX: Passing the secret as an argument is not ideal as it
                   # could theoretically be read from the process table, but
                   # the security command does not provide a way to read the
                   # password from stdin non-interactively.
                   '-w', secret]
        if update:
            command.append('-U')
        if keychain:
            command.append(keychain)

        result = subprocess.run(command)
        logger.debug("security add-generic-password rc: %d", result.returncode)
        if result.returncode:
            raise KeychainError("Failed to save secret to keychain")

    def retrieve_secret(self, name, keychain=None):
        """Retrieve the secret for the given credential name."""
        raise NotImplementedError()

    def delete_secret(self, name, keychain=None):
        """Delete the secret for the given credential name."""
        raise NotImplementedError()


class MetadataStore:
    """Class for storing and retrieving credential metadata."""

    def __init__(self, filename):
        self.connection = sqlite3.connect(filename)
        self.connection.row_factory = sqlite3.Row
        self._create_table()

    def _create_table(self):
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS twofa_metadata(
                name TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                label TEXT,
                issuer TEXT,
                algorithm TEXT,
                digits INTEGER,
                period INTEGER,
                counter INTEGER,
                keychain TEXT
            )
        """)

    def store_metadata(self, name, otp_type, label=None, issuer=None,
                       algorithm=None, digits=None, period=None, counter=None,
                       keychain=None, update=False):
        """Store metadata for the given credential."""
        operation = 'REPLACE' if update else 'INSERT'
        with self.connection:
            self.connection.execute(
                f"{operation} INTO twofa_metadata (name, type, label, issuer, "
                "algorithm, digits, period, counter, keychain) VALUES (?, ?, "
                "?, ?, ?, ?, ?, ?, ?)",
                (name, otp_type, label, issuer, algorithm, digits, period,
                 counter, keychain))

    def retrieve_metadata(self, name):
        """Retrieve metadata for the given credential."""
        return self.connection.execute(
            "SELECT name, type, label, issuer, algorithm, digits, period, "
            "counter, keychain FROM twofa_metadata WHERE name = ?",
            (name,)).fetchone()

    def retrieve_all_metadata(self):
        """Retrieve metadata for all credentials."""
        return self.connection.execute(
            "SELECT name, type, label, issuer, algorithm, digits, period, "
            "counter, keychain FROM twofa_metadata").fetchall()

    def increment_hotp_counter(self, name):
        """Increment the counter for the given HOTP credential."""
        with self.connection:
            return self.connection.execute(
                "UPDATE twofa_metadata SET counter = counter + 1 "
                "WHERE name = ?", (name,)).rowcount

    def delete_metadata(self, name):
        """Delete metadata for the given credential."""
        with self.connection:
            return self.connection.execute(
                "DELETE FROM twofa_metadata WHERE name = ?", (name,)).rowcount

    def close(self):
        self.connection.close()


### High-level operations

class CredentialManager:
    """Class to manage 2FA credentials"""

    def __init__(self, secret_store, metadata_store):
        self.secret_store = secret_store
        self.metadata_store = metadata_store

    def add_credential(self, name, otp_type, secret, label=None, issuer=None,
                       algorithm=None, digits=None, period=None, counter=None,
                       keychain=None, update=False):
        """Persist a credential."""
        if not update and self.metadata_store.retrieve_metadata(name):
            raise CredentialExistsError(
                f"Found existing credential with name {name!r}.")
        self.metadata_store.store_metadata(
            name=name,
            otp_type=otp_type,
            label=label, issuer=issuer,
            algorithm=algorithm, digits=digits,
            period=period, counter=counter,
            keychain=keychain, update=update)
        self.secret_store.store_secret(name, secret, keychain, update)

    def get_otp(self, name):
        """Get an OTP for the given credential."""
        raise NotImplementedError()

    def get_url(self, name):
        """Get an otpauth URL for the given credential."""
        raise NotImplementedError()

    def delete(self, name):
        """Delete the given credential."""
        raise NotImplementedError()

    def get_all_metadata(self):
        """Retrieve metadata for all credentials."""
        raise NotImplementedError()

    def close(self):
        self.metadata_store.close()


### Command-line parsing

def create_parser():
    """Create argument parser for the tool."""
    parser = ArgumentParser(
        description="A command-line tool for TOTP/HOTP authentication using "
        "the Mac OS keychain to store secrets.")

    parser.add_argument('--debug', '-d', action='store_true', help="Enable "
                        "debug logging")
    parser.add_argument('--db-path', '-p', help="Path to metadata db file")

    subparsers = parser.add_subparsers(required=True, dest='command')
    init_add_parser(subparsers)
    init_addurl_parser(subparsers)
    init_getotp_parser(subparsers)
    init_geturl_parser(subparsers)
    init_delete_parser(subparsers)
    init_list_parser(subparsers)

    return parser


def add_name_arg(cmd_parser):
    """Add common --name argument to the given subparser."""
    cmd_parser.add_argument('--name', '-n', required=True, help="A name used "
                            "to uniquely identify the credential")


def add_add_args(cmd_parser):
    """Add common arguments for adding credentials to the given subparser."""
    cmd_parser.add_argument('--keychain', '-k', help="Keychain in which to "
                            "store the secret")
    cmd_parser.add_argument('--update', '-u', action='store_true',
                            help="Update an existing credential")


def init_add_parser(subparsers):
    """Initialize subparser for the add command."""
    add_parser = subparsers.add_parser('add', help="Add or update an OTP "
                                       "credential")
    add_name_arg(add_parser)
    type_group = add_parser.add_mutually_exclusive_group(required=True)
    type_group.add_argument('--totp', '-T', dest='type', action='store_const',
                            const='totp', help="Create a TOTP credential")
    type_group.add_argument('--hotp', '-H', dest='type', action='store_const',
                            const='hotp', help="Create an HOTP credential")
    add_parser.add_argument('--label', '-l', help="Optional value indicating "
                            "the account the credential is associated with")
    add_parser.add_argument('--issuer', '-i', help="Optional value indicating "
                            "the provider or service the credential is "
                            "associated with")
    add_parser.add_argument('--algorithm', '-a',
                            choices=('SHA1', 'SHA256', 'SHA512'),
                            help="Credential hash digest algorithm")
    add_parser.add_argument('--digits', '-d', type=int, choices=(6, 7, 8),
                            help="Number of OTP digits")
    add_parser.add_argument('--period', '-p', type=int,
                            help="Validity period  in seconds for a TOTP "
                            "credential")
    add_parser.add_argument('--counter', '-c', type=int, help="Initial "
                            "counter value for an HOTP credential")
    add_add_args(add_parser)


def init_addurl_parser(subparsers):
    """Initialize subparser for the addurl command."""
    pass  # TODO


def init_getotp_parser(subparsers):
    """Initialize subparser for the getotp command."""
    pass  # TODO


def init_geturl_parser(subparsers):
    """Initialize subparser for the geturl command."""
    pass  # TODO


def init_delete_parser(subparsers):
    """Initialize subparser for the delete command."""
    pass  # TODO


def init_list_parser(subparsers):
    """Initialize subparser for the list command."""
    pass  # TODO


### Input validation

def validate_secret(input_secret):
    """Validate and normalize a base32 secret from user input."""
    trans = str.maketrans(string.ascii_lowercase, string.ascii_uppercase, '- ')
    secret = input_secret.translate(trans)
    try:
        base64.b32decode(secret)
    except (binascii.Error, ValueError) as e:
        raise ValidationError("Secret must be a valid base32-encoded string") \
             from e
    return secret


def validate_algorithm(algorithm):
    if algorithm is None:
        return None
    if algorithm not in ('SHA1', 'SHA256', 'SHA512'):
        raise ValidationError("Algorithm must be one of: SHA1, SHA256, SHA512")
    return algorithm


def validate_digits(digits):
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
    try:
        counter = int(counter)
    except ValueError as e:
        raise ValidationError("Counter must be a valid integer value") from e
    return counter


def validate_period(period):
    if period is None:
        return None
    try:
        period = int(period)
    except ValueError as e:
        raise ValidationError("Period must be a valid integer value") from e
    if period <= 0:
        raise ValidationError("Period must be greater than 0")
    return period


### Command execution

def get_db_path(path):
    if path is None:
        path = os.environ.get('TWOFA_DB_PATH')
    if path is None:
        path = os.expanduser("~/.twofa.db")
    logger.debug("Metadata db path: %r", path)
    return path


def input_secret(prompt):
    """Read a secret value from stdin or prompt in a TTY."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    else:
        return sys.stdin.read().strip()


def do_add_command(credential_manager, args):
    params = {}
    if args.type == 'totp':
        params['period'] = validate_period(args.period)
        if args.counter is not None:
            logger.warning("Ignoring --counter for TOTP credential")
    elif args.type == 'hotp':
        params['counter'] = args.counter or 0
        if args.period is not None:
            logger.warning("Ignoring --period for HOTP credential")
    else:
        raise ValueError(f"Invalid credential type: {args.type!r}")

    secret = input_secret('Secret: ')
    credential_manager.add_credential(
        name=args.name,
        otp_type=args.type,
        secret=validate_secret(secret),
        label=args.label,
        issuer=args.issuer,
        algorithm=validate_algorithm(args.algorithm),
        digits=validate_digits(args.digits),
        keychain=args.keychain or os.environ.get('TWOFA_DEFAULT_KEYCHAIN'),
        update=args.update,
        **params)


def handle_args(args):
    """Process parsed args and execute command."""
    secret_store = SecretStore()
    metadata_store = MetadataStore(get_db_path(args.db_path))
    credential_manager = CredentialManager(secret_store, metadata_store)

    command = args.command
    if command == 'add':
        do_add_command(credential_manager, args)
    elif command == 'addurl':
        raise NotImplementedError()
    elif command == 'getotp':
        raise NotImplementedError()
    elif command == 'geturl':
        raise NotImplementedError()
    elif command == 'delete':
        raise NotImplementedError()
    elif command == 'list':
        raise NotImplementedError()
    else:
        raise ValueError(f"Invalid command: {args.command!r}")


def init_logging(args):
    """Initialize logging subsystem."""
    logging.basicConfig(level=logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    init_logging(args)
    try:
        handle_args(args)
    except TwofaError as e:
        logger.debug("Command failed", exc_info=True)
        logger.error("%s", e)
        if isinstance(e, CredentialExistsError):
            logger.info("Use --update to replace existing value.")
        exit(1)
