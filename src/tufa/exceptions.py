"""Exceptions raised by tufa."""


class TufaError(Exception):
    """Base exception type for this package."""
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
