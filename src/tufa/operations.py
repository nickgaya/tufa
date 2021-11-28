"""High-level operations."""

import logging
import os.path
import shlex
import urllib.parse

from .metadata import CredentialMetadata
from .otp import get_hotp, get_totp
from .exceptions import (
    CredentialExistsError,
    CredentialNotFoundError,
    KeychainError,
)

logger = logging.getLogger(__name__)


class CredentialManager:
    """Class to manage 2FA credentials"""

    def __init__(self, secret_store, metadata_store):
        self.secret_store = secret_store
        self.metadata_store = metadata_store

    def _check_keychain(self, keychain):
        if not keychain:
            return
        try:
            self.secret_store.verify_keychain(keychain)
        except KeychainError as e:
            if '/' not in keychain and not keychain.endswith('.keychain'):
                suggestion = f'{keychain}.keychain'
                if os.path.exists(os.path.expanduser(
                        f'~/Library/Keychains/{suggestion}-db')):
                    e.info = f"Try --keychain {shlex.quote(suggestion)}"
            raise

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
            otp = get_hotp(secret, metadata.counter,
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
                           ('digits', metadata.digits)):
            if value is not None:
                params[key] = str(value)
        if metadata.type == 'totp':
            if metadata.period is not None:
                params['period'] = str(metadata.period)
        elif metadata.type == 'hotp':
            params['counter'] = str(metadata.counter or 0)
        else:
            raise ValueError(f"Invalid metadata type: {metadata.type!r}")
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
