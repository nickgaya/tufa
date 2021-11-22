import base64
import binascii
import getpass
import hmac
import logging
import os
import os.path
import shlex
import sqlite3
import string
import struct
import subprocess
import sys
import time
import urllib.parse
from argparse import ArgumentParser
from collections import namedtuple

logger = logging.getLogger('tufa')

_SECURITY = '/usr/bin/security'


# Exceptions

class TufaError(Exception):
    """Base exception type for this script."""
    rc = 1  # Return code for this error
    info = None  # Extra info to log for this error


class UserError(TufaError):
    """Exception type used to indicate user error."""


class ValidationError(UserError):
    """Exception type used to indicate invalid user input."""


class CredentialExistsError(UserError):
    """Exception type when the user attempts to add an existing credential."""
    info = "Use --update to replace existing value."
    rc = 2


class CredentialNotFoundError(UserError):
    """Exception type when the user references a nonexistent credential."""
    rc = 3


class KeychainError(TufaError):
    """"Exception type for errors interacting with Mac OS keychain."""
    rc = 4


# OTP generation

def decode_secret(secret):
    return base64.b32decode(secret + '=' * (-len(secret) % 8))


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
    secret_bytes = decode_secret(secret)
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


# Persistence layer

class SecretStore:
    """Class for storing and retrieving secrets in the Mac OS keychain."""

    def __init__(self, service=None):
        self.service = service or 'tufa'

    def _run_command(self, command, args, redact_arg=None, log_stdout=True):
        """Execute a security command."""
        cmd_args = [_SECURITY, command, *args]
        if logger.isEnabledFor(logging.DEBUG):
            cmd_str = ' '.join(
                '****' if i-2 == redact_arg else shlex.quote(arg)
                for i, arg in enumerate(cmd_args))
            logger.debug("Executing command: %s", cmd_str)
        result = subprocess.run(cmd_args, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True,
                                start_new_session=True)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Command returncode: %d", result.returncode)
            if result.stdout and log_stdout:
                logger.debug("Command output:\n%s", result.stdout.rstrip('\n'))
            if result.stderr:
                logger.debug("Command error output:\n%s",
                             result.stderr.rstrip('\n'))
        return result

    def store_secret(self, name, secret, keychain=None, update=False):
        """Store a secret for the given credential name."""
        args = [
            # The service and account parameters together uniquely identify a
            # keychain item
            '-s', self.service, '-a', name,
            # Additional display parameters shown in Keychain Access
            '-l', f'{self.service}: {name}',
            '-D', 'hotp/totp secret',
            # XXX: Passing the secret as an argument is not ideal as it could
            # theoretically be read from the process table, but the security
            # command does not provide a way to read the password from stdin
            # non-interactively.
            '-w', secret,
        ]
        secret_idx = len(args) - 1
        if update:
            args.append('-U')
        if keychain:
            args.append(keychain)

        result = self._run_command(
            'add-generic-password', args, redact_arg=secret_idx)
        if result.returncode:
            raise KeychainError("Failed to save secret to keychain")

    def retrieve_secret(self, name, keychain=None):
        """Retrieve the secret for the given credential name."""
        args = ['-s', self.service, '-a', name, '-w']
        if keychain:
            args.append(keychain)
        result = self._run_command(
            'find-generic-password', args, log_stdout=False)
        if result.returncode:
            raise KeychainError("Failed to retrieve secret from keychain")
        return result.stdout.strip()

    def delete_secret(self, name, keychain=None):
        """Delete the secret for the given credential name."""
        args = ['-s', self.service, '-a', name]
        if keychain:
            args.append(keychain)
        result = self._run_command('delete-generic-password', args)
        if result.returncode:
            raise KeychainError("Failed to delete secret from keychain")

    def verify_keychain(self, keychain):
        """Check whether the given keychain exists."""
        # We use the show-keychain-info command to verify that the specified
        # keychain actually exists. This command will also unlock the given
        # keychain, prompting the user for a password if necessary.
        result = self._run_command('show-keychain-info', [keychain])
        return result.returncode == 0


CredentialMetadata = namedtuple(
    'CredentialMetadata', ('name', 'type', 'label', 'issuer', 'algorithm',
                           'digits', 'period', 'counter', 'keychain'))


class MetadataStore:
    """Class for storing and retrieving credential metadata."""

    def __init__(self, db_path):
        self.connection = sqlite3.connect(db_path)
        self._create_table()

    def _create_table(self):
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS tufa_metadata(
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

    def store_metadata(self, metadata, update=False):
        """Store metadata for the given credential."""
        operation = 'REPLACE' if update else 'INSERT'
        with self.connection:
            self.connection.execute(
                f"{operation} INTO tufa_metadata (name, type, label, issuer, "
                "algorithm, digits, period, counter, keychain) VALUES (?, ?, "
                "?, ?, ?, ?, ?, ?, ?)", metadata)

    def retrieve_metadata(self, name):
        """Retrieve metadata for the given credential."""
        row = self.connection.execute(
            "SELECT name, type, label, issuer, algorithm, digits, period, "
            "counter, keychain FROM tufa_metadata WHERE name = ?",
            (name,)).fetchone()
        return CredentialMetadata(*row) if row else None

    def retrieve_all_metadata(self):
        """Retrieve metadata for all credentials."""
        return [CredentialMetadata(*row) for row in self.connection.execute(
            "SELECT name, type, label, issuer, algorithm, digits, period, "
            "counter, keychain FROM tufa_metadata ORDER BY name")]

    def increment_hotp_counter(self, name):
        """Increment the counter for the given HOTP credential."""
        with self.connection:
            return self.connection.execute(
                "UPDATE tufa_metadata SET counter = counter + 1 "
                "WHERE name = ?", (name,)).rowcount

    def delete_metadata(self, name):
        """Delete metadata for the given credential."""
        with self.connection:
            return self.connection.execute(
                "DELETE FROM tufa_metadata WHERE name = ?", (name,)).rowcount

    def close(self):
        """Close the underlying db connection."""
        self.connection.close()


# High-level operations

class CredentialManager:
    """Class to manage 2FA credentials"""

    def __init__(self, secret_store, metadata_store):
        self.secret_store = secret_store
        self.metadata_store = metadata_store

    def _check_keychain(self, keychain):
        if not keychain:
            return
        if self.secret_store.verify_keychain(keychain):
            return
        error = KeychainError(f"Unable to access keychain {keychain!r}")
        if '/' not in keychain and not keychain.endswith('.keychain'):
            suggestion = f'{keychain}.keychain'
            if os.path.exists(os.path.expanduser(
                    f'~/Library/Keychains/{suggestion}-db')):
                error.info = f"Try --keychain {shlex.quote(suggestion)}"
        raise error

    def add_credential(self, name, type_, secret, label=None, issuer=None,
                       algorithm=None, digits=None, period=None, counter=None,
                       keychain=None, update=False):
        """Persist a credential."""

        # If the keychain supplied to add-generic-password is not found, the
        # command silently adds the password to the default keychain. Because
        # of this, we check for keychain existence before adding a new
        # credential.
        self._check_keychain(keychain)

        old_metadata = self.metadata_store.retrieve_metadata(name)
        if old_metadata:
            if not update:
                raise CredentialExistsError(
                    f"Found existing credential with name {name!r}.")
            if old_metadata.keychain != keychain:
                logger.info(
                    "Deleting existing secret from %s",
                    old_metadata.keychain or 'default keychain')
                self.secret_store.delete_secret(name, old_metadata.keychain)

        self.secret_store.store_secret(name, secret, keychain, update)
        metadata = CredentialMetadata(
            name=name,
            type=type_,
            label=label,
            issuer=issuer,
            algorithm=algorithm,
            digits=digits,
            period=period,
            counter=counter,
            keychain=keychain,
        )
        self.metadata_store.store_metadata(metadata, update=update)

    def _get_credential(self, name):
        """Get credential metadata and secret."""
        metadata = self.metadata_store.retrieve_metadata(name)
        if not metadata:
            raise CredentialNotFoundError(
                f"No credential found with name {name!r}")
        secret = self.secret_store.retrieve_secret(
            name, keychain=metadata.keychain)
        return metadata, secret

    def get_otp(self, name):
        """
        Get a one-time password for the given credential.

        If the credential is of type HOTP, increment the counter.
        """
        metadata, secret = self._get_credential(name)
        if metadata.type == 'totp':
            return get_totp(secret, metadata.period,
                            metadata.algorithm, metadata.digits)
        elif metadata.type == 'hotp':
            otp = get_otp(secret, metadata.counter,
                          metadata.algorithm, metadata.digits)
            self.metadata_store.increment_hotp_counter(name)
            return otp
        else:
            raise ValueError(f"Invalid metadata type: {metadata.type!r}")

    def get_url(self, name):
        """Get an otpauth URL for the given credential."""
        metadata, secret = self._get_credential(name)
        label = urllib.parse.quote(metadata.label or metadata.name)
        params = {
            'secret': secret,
        }
        for key, value in (('issuer', metadata.issuer),
                           ('algorithm', metadata.algorithm),
                           ('digits', metadata.digits),
                           ('period', metadata.period),
                           ('counter', metadata.counter)):
            if value is not None:
                params[key] = str(value)
        qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        return f'otpauth://{metadata.type}/{label}?{qs}'

    def delete_credential(self, name, force=False):
        """Delete the given credential."""
        metadata = self.metadata_store.retrieve_metadata(name)
        if not metadata:
            raise CredentialNotFoundError(
                f"No credential found with name {name!r}")
        try:
            self.secret_store.delete_secret(name, keychain=metadata.keychain)
        except KeychainError as e:
            if force:
                logger.warning(
                    "%s", e, exc_info=logger.isEnabledFor(logging.DEBUG))
            else:
                e.info = "Use --force to delete metadata anyway"
                raise
        self.metadata_store.delete_metadata(name)

    def get_all_metadata(self):
        """Retrieve metadata for all credentials."""
        return self.metadata_store.retrieve_all_metadata()


# Command-line parsing

def create_parser():
    """Create argument parser for the tool."""
    parser = ArgumentParser(
        description="A command-line tool for TOTP/HOTP authentication using "
        "the Mac OS keychain to store secrets.")

    parser.add_argument('--debug', '-d', action='store_true', help="Enable "
                        "debug logging")
    parser.add_argument('--db-path', '-p', help="Path to the metadata db file")

    subparsers = parser.add_subparsers(required=True, dest='command')
    init_add_parser(subparsers.add_parser(
        'add', help="Add or update an OTP credential"))
    init_addurl_parser(subparsers.add_parser(
        'addurl', help="Add an OTP credential as an otpauth:// URL"))
    init_getotp_parser(subparsers.add_parser(
        'getotp', help="Get a one-time password"))
    init_geturl_parser(subparsers.add_parser(
        'geturl', help="Generate a otpauth:// URL for a credential"))
    init_delete_parser(subparsers.add_parser(
        'delete', help="Delete a credential"))
    init_list_parser(subparsers.add_parser(
        'list', help="List credentials"))

    return parser


def add_name_arg(parser):
    """Add common --name argument to the given subparser."""
    parser.add_argument('--name', '-n', required=True, help="Credential name")


def add_add_args(parser):
    """Add common arguments for adding credentials to the given subparser."""
    parser.add_argument('--keychain', '-k',
                        default=os.environ.get('TUFA_DEFAULT_KEYCHAIN'),
                        help="Keychain in which to store the secret")
    parser.add_argument('--update', '-u', action='store_true',
                        help="Update an existing credential")


def init_add_parser(parser):
    """Initialize subparser for the add command."""
    add_name_arg(parser)
    type_group = parser.add_mutually_exclusive_group(required=True)
    type_group.add_argument('--totp', '-T', dest='type', action='store_const',
                            const='totp', help="Create a TOTP credential")
    type_group.add_argument('--hotp', '-H', dest='type', action='store_const',
                            const='hotp', help="Create an HOTP credential")
    parser.add_argument('--label', '-l', help="The account the credential is "
                        "associated with")
    parser.add_argument('--issuer', '-i', help="The provider or service the "
                        "credential is associated with")
    parser.add_argument('--algorithm', '-a',
                        choices=('SHA1', 'SHA256', 'SHA512'),
                        help="Credential hash digest algorithm (default SHA1)")
    parser.add_argument('--digits', '-d', type=int, choices=(6, 7, 8),
                        help="Number of OTP digits (default 6)")
    parser.add_argument('--period', '-p', type=int,
                        help="Validity period  in seconds for a TOTP "
                        "credential (default 30)")
    parser.add_argument('--counter', '-c', type=int, help="Initial counter "
                        "value for an HOTP credential (default 0)")
    add_add_args(parser)


def init_addurl_parser(parser):
    """Initialize subparser for the addurl command."""
    add_name_arg(parser)
    add_add_args(parser)


def init_getotp_parser(parser):
    """Initialize subparser for the getotp command."""
    add_name_arg(parser)


def init_geturl_parser(parser):
    """Initialize subparser for the geturl command."""
    add_name_arg(parser)


def init_delete_parser(parser):
    """Initialize subparser for the delete command."""
    add_name_arg(parser)
    parser.add_argument('--force', '-f', action='store_true',
                        help="Delete credential metadata from the db even if "
                        "deleting the secret from the keychain fails")


def init_list_parser(parser):
    """Initialize subparser for the list command."""
    parser.add_argument('--table', '-t', action='store_true',
                        help="Display full metadata in tabular format")


# Input validation

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


# Command execution

def get_db_path(path):
    """Get metadata database path."""
    if not path:
        path = os.environ.get('TUFA_DB_PATH')
    if not path:
        path = os.path.expanduser("~/.tufa.sqlite3")
    logger.debug("Metadata db path: %r", path)
    return path


def input_secret(prompt):
    """Read a secret value from stdin or prompt in a TTY."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    else:
        return sys.stdin.read().strip()


def do_add_command(credential_manager, args):
    """Perform add command."""
    params = {}
    if args.type == 'totp':
        params['period'] = validate_period(args.period)
        if args.counter is not None:
            logger.warning("Ignoring --counter for TOTP credential")
    elif args.type == 'hotp':
        params['counter'] = validate_counter(args.counter or 0)
        if args.period is not None:
            logger.warning("Ignoring --period for HOTP credential")
    else:
        raise ValueError(f"Invalid credential type: {args.type!r}")

    secret = input_secret('Secret: ')
    credential_manager.add_credential(
        name=args.name,
        type_=args.type,
        secret=validate_secret(secret),
        label=args.label,
        issuer=args.issuer,
        algorithm=validate_algorithm(args.algorithm),
        digits=validate_digits(args.digits),
        **params,
        keychain=args.keychain or None,
        update=args.update)
    logger.info("Credential %r added", args.name)


def do_addurl_command(credential_manager, args):
    """Perform addurl command."""
    url = input_secret('URL: ')
    params = {}
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError as e:
        raise ValidationError("Malformed URL") from e

    if parts.scheme != 'otpauth':
        raise ValidationError("URL must have scheme otpauth://")

    type_ = validate_type(parts.netloc)

    label = urllib.parse.unquote(parts.path)
    if label and label.startswith('/'):
        label = label[1:]
    if not label:
        logger.warning("URL has empty or missing label")

    if parts.params:
        logger.warning("Ignoring URL path parameters: %r", parts.params)
    if parts.fragment:
        logger.warning("Ignoring URL fragment: %r", parts.fragment)

    try:
        query_params = urllib.parse.parse_qs(parts.query, strict_parsing=True)
    except ValueError as e:
        raise ValidationError("Malformed query parameters") from e

    validators = {
        'secret': validate_secret,
        'issuer': lambda x: x,
        'algorithm': validate_algorithm,
        'digits': validate_digits,
    }
    if type_ == 'totp':
        validators['period'] = validate_period
    elif type_ == 'hotp':
        validators['counter'] = validate_counter
    params = {}
    for key, values in query_params.items():
        if key in validators:
            if len(values) > 1:
                logger.warning("Multiple values for parameter: %r", key)
            params[key] = validators[key](values[0])
        else:
            logger.warning("Ignoring unknown query parameter: %r", key)
    if 'secret' not in params:
        raise ValidationError("Missing parameter 'secret'")
    if type_ == 'hotp' and 'counter' not in params:
        logger.warning("Missing parameter 'counter' for HOTP, defaulting to 0")
        params['counter'] = 0

    credential_manager.add_credential(
        name=args.name,
        type_=type_,
        label=label,
        **params,
        keychain=args.keychain or None,
        update=args.update)
    logger.info("Credential %r added", args.name)


def do_getotp_command(credential_manager, args):
    """Perform getotp command."""
    print(credential_manager.get_otp(args.name))


def do_geturl_command(credential_manager, args):
    """Perform geturl command."""
    print(credential_manager.get_url(args.name))


def do_delete_command(credential_manager, args):
    """Perform delete command."""
    credential_manager.delete_credential(args.name, force=args.force)
    logger.info("Credential %r deleted", args.name)


def do_list_command(credential_manager, args):
    """Perform list command."""
    metadata_list = credential_manager.get_all_metadata()
    if args.table:
        # TODO: Nicer table?
        print('\t'.join(name.capitalize()
                        for name in CredentialMetadata._fields))
        for metadata in metadata_list:
            print('\t'.join('' if item is None else str(item)
                            for item in metadata))
    else:
        for metadata in metadata_list:
            print(metadata.name)


def do_command(args):
    """Process parsed args and execute command."""
    secret_store = SecretStore()
    metadata_store = MetadataStore(get_db_path(args.db_path))
    credential_manager = CredentialManager(secret_store, metadata_store)

    command = args.command
    if command == 'add':
        do_add_command(credential_manager, args)
    elif command == 'addurl':
        do_addurl_command(credential_manager, args)
    elif command == 'getotp':
        do_getotp_command(credential_manager, args)
    elif command == 'geturl':
        do_geturl_command(credential_manager, args)
    elif command == 'delete':
        do_delete_command(credential_manager, args)
    elif command == 'list':
        do_list_command(credential_manager, args)
    else:
        raise ValueError(f"Invalid command: {args.command!r}")


def init_logging(args):
    """Initialize logging subsystem."""
    logging.basicConfig(level=logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)


def main():
    parser = create_parser()
    args = parser.parse_args()
    init_logging(args)
    try:
        do_command(args)
    except TufaError as e:
        logger.error("%s", e, exc_info=args.debug)
        if e.info:
            logger.info(e.info)
        return e.rc
    except KeyboardInterrupt:
        logger.info("Interrupted", exc_info=args.debug)
        return 1
