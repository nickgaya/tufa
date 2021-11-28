"""Command execution."""

import getpass
import logging
import os
import os.path
import sys
import urllib.parse

from .exceptions import ValidationError
from .metadata import CredentialMetadata, MetadataStore
from .operations import CredentialManager
from .secrets import SecretStore
from .validation import (
    validate_algorithm,
    validate_counter,
    validate_digits,
    validate_period,
    validate_secret,
    validate_type,
)

logger = logging.getLogger(__name__)


def _get_db_path(path):
    """Get metadata database path."""
    if not path:
        path = os.environ.get('TUFA_DB_PATH')
    if not path:
        path = os.path.expanduser("~/.tufa.sqlite3")
    logger.debug("Metadata db path: %r", path)
    return path


def _input_secret(prompt):
    """Read a secret value from stdin or prompt in a TTY."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt).strip()
    else:
        return sys.stdin.read().strip()


def _get_keychain(keychain):
    if keychain is None:
        keychain = os.environ.get('TUFA_DEFAULT_KEYCHAIN')
    return keychain or None


def _do_add_command(credential_manager, args):
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

    secret = _input_secret('Secret: ')
    credential_manager.add_credential(
        name=args.name,
        type_=args.type,
        secret=validate_secret(secret),
        label=args.label,
        issuer=args.issuer,
        algorithm=validate_algorithm(args.algorithm),
        digits=validate_digits(args.digits),
        **params,
        keychain=_get_keychain(args.keychain),
        update=args.update)
    logger.info("Credential %r added", args.name)


def _do_addurl_command(credential_manager, args):
    """Perform addurl command."""
    url = _input_secret('URL: ')
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
        label = None

    if parts.params:
        logger.warning("Ignoring URL path parameters: %r", parts.params)
    if parts.fragment:
        logger.warning("Ignoring URL fragment: %r", parts.fragment)

    try:
        # Need to check for empty qs due to https://bugs.python.org/issue45874
        query_params = (urllib.parse.parse_qs(parts.query, strict_parsing=True)
                        if parts.query else {})
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
        keychain=_get_keychain(args.keychain),
        update=args.update)
    logger.info("Credential %r added", args.name)


def _do_getotp_command(credential_manager, args):
    """Perform getotp command."""
    print(credential_manager.get_otp(args.name))


def _do_geturl_command(credential_manager, args):
    """Perform geturl command."""
    print(credential_manager.get_url(args.name))


def _do_delete_command(credential_manager, args):
    """Perform delete command."""
    credential_manager.delete_credential(args.name, force=args.force)
    logger.info("Credential %r deleted", args.name)


def _do_list_command(credential_manager, args):
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
    metadata_store = MetadataStore(_get_db_path(args.db_path))
    credential_manager = CredentialManager(secret_store, metadata_store)

    command = args.command
    if command == 'add':
        _do_add_command(credential_manager, args)
    elif command == 'addurl':
        _do_addurl_command(credential_manager, args)
    elif command == 'getotp':
        _do_getotp_command(credential_manager, args)
    elif command == 'geturl':
        _do_geturl_command(credential_manager, args)
    elif command == 'delete':
        _do_delete_command(credential_manager, args)
    elif command == 'list':
        _do_list_command(credential_manager, args)
    else:
        raise ValueError(f"Invalid command: {args.command!r}")
