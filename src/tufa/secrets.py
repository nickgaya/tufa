"""Secret storage and retrieval."""

import logging
import shlex
import subprocess

from .exceptions import KeychainError

logger = logging.getLogger(__name__)

_SECURITY = '/usr/bin/security'


class SecretStore:
    """Class for storing and retrieving secrets in the Mac OS keychain."""

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
            '-s', 'tufa', '-a', name,
            # Additional display parameters shown in Keychain Access
            '-l', f'tufa: {name}',
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
        args = ['-s', 'tufa', '-a', name, '-w']
        if keychain:
            args.append(keychain)
        result = self._run_command(
            'find-generic-password', args, log_stdout=False)
        if result.returncode:
            raise KeychainError("Failed to retrieve secret from keychain")
        return result.stdout.strip()

    def delete_secret(self, name, keychain=None):
        """Delete the secret for the given credential name."""
        args = ['-s', 'tufa', '-a', name]
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
        if result.returncode != 0:
            raise KeychainError(f"Unable to access keychain {keychain!r}")
