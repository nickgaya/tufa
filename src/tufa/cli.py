"""Command-line parsing."""

from argparse import ArgumentParser


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
