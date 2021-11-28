"""Tests of tufa argument parsing/validation and command execution."""

from unittest import mock

import pytest

from tufa.cli import create_parser
from tufa.commands import do_command
from tufa.exceptions import ValidationError
from tufa.metadata import CredentialMetadata


@pytest.fixture
def parser():
    return create_parser()


@pytest.fixture(autouse=True)
def mock_os(mocker):
    mock_os = mocker.patch('tufa.commands.os', autospec=True)
    mock_os.environ.get.return_value = None
    mock_os.path.expanduser.return_value = mock.sentinel.db_path
    return mock_os


@pytest.fixture(autouse=True)
def mock_sys(mocker):
    mock_sys = mocker.patch('tufa.commands.sys', autospec=True)
    mock_sys.stdin.isatty.return_value = False
    return mock_sys


@pytest.fixture(autouse=True)
def mocks(mocker):
    mocks = mock.MagicMock(name='mocks')

    mock_SecretStore = mocker.patch('tufa.commands.SecretStore', autospec=True)
    mocks.attach_mock(mock_SecretStore, 'SecretStore')

    mock_MetadataStore = mocker.patch('tufa.commands.MetadataStore',
                                      autospec=True)
    mocks.attach_mock(mock_MetadataStore, 'MetadataStore')

    mock_CredentialManager = mocker.patch('tufa.commands.CredentialManager',
                                          autospec=True)
    mock_CredentialManager.return_value = mocks.credential_manager
    mocks.attach_mock(mock_CredentialManager, 'CredentialManager')
    return mocks


def test_add_totp(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = 'TEST'

    do_command(parser.parse_args(['add', '--name', 'test-name', '--totp']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='totp', secret='TEST', label=None, issuer=None,
        algorithm=None, digits=None, period=None, keychain=None, update=False)


def test_add_totp_params(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = 'TEST'

    do_command(parser.parse_args([
        'add', '--name', 'test-name', '--totp',
        '--label', 'test-label', '--issuer', 'test-issuer',
        '--algorithm', 'SHA256', '--digits', '7', '--period', '15',
        '--keychain', 'test.keychain', '--update']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='totp', secret='TEST', label='test-label',
        issuer='test-issuer', algorithm='SHA256', digits=7, period=15,
        keychain='test.keychain', update=True)


def test_add_hotp(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = 'TEST'

    do_command(parser.parse_args(['add', '--name', 'test-name', '--hotp']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='hotp', secret='TEST', label=None, issuer=None,
        algorithm=None, digits=None, counter=0, keychain=None, update=False)


def test_add_hotp_params(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = 'TEST'

    do_command(parser.parse_args([
        'add', '--name', 'test-name', '--hotp',
        '--label', 'test-label', '--issuer', 'test-issuer',
        '--algorithm', 'SHA256', '--digits', '7', '--counter', '125',
        '--keychain', 'test.keychain', '--update']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='hotp', secret='TEST', label='test-label',
        issuer='test-issuer', algorithm='SHA256', digits=7, counter=125,
        keychain='test.keychain', update=True)


def test_addurl_totp(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = 'otpauth://totp/test-label?secret=TEST'

    do_command(parser.parse_args(['addurl', '--name', 'test-name']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='totp', label='test-label', secret='TEST',
        keychain=None, update=False)


def test_addurl_totp_params(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = \
        'otpauth://totp/test-label?secret=TEST&issuer=test-issuer' \
        '&algorithm=SHA1&digits=6&period=60'

    do_command(parser.parse_args(['addurl', '--name', 'test-name',
                                  '--keychain', 'test.keychain', '--update']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='totp', label='test-label', secret='TEST',
        issuer='test-issuer', algorithm='SHA1', digits=6, period=60,
        keychain='test.keychain', update=True)


def test_addurl_hotp(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = \
        'otpauth://hotp/test-label?secret=TEST&counter=1'

    do_command(parser.parse_args(['addurl', '--name', 'test-name']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='hotp', label='test-label', secret='TEST',
        counter=1, keychain=None, update=False)


def test_addurl_hotp_params(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = \
        'otpauth://hotp/test-label?secret=TEST&issuer=test-issuer' \
        '&algorithm=SHA1&digits=6&counter=1234'

    do_command(parser.parse_args(['addurl', '--name', 'test-name',
                                  '--keychain', 'test.keychain', '--update']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='hotp', label='test-label', secret='TEST',
        issuer='test-issuer', algorithm='SHA1', digits=6, counter=1234,
        keychain='test.keychain', update=True)


def test_addurl_hotp_default_counter(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = 'otpauth://hotp/test-label?secret=TEST'

    do_command(parser.parse_args(['addurl', '--name', 'test-name']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='hotp', label='test-label', secret='TEST',
        counter=0, keychain=None, update=False)


@pytest.mark.parametrize('url', [
    '',
    'invalid',
    'L36J-V7UW-X2IK-RKG4',
    'otpauth://[::',
    'http://github.com/nickgaya',
    '/totp/test-label?secret=TEST',
    'otpauth://invalid/test-label?secret=TEST',
    'otpauth://hotp/test-label',
    'otpauth://hotp/test-label?',
    'otpauth://totp/test-label?invalid',
    'otpauth://hotp/test-label?secret=10',
])
def test_addurl_invalid(parser, mocks, mock_sys, url):
    mock_sys.stdin.read.return_value = url

    args = parser.parse_args(['addurl', '--name', 'test-name'])
    with pytest.raises(ValidationError):
        do_command(args)


def test_addurl_no_label(parser, mocks, mock_sys):
    mock_sys.stdin.read.return_value = 'otpauth://totp?secret=TEST'

    do_command(parser.parse_args(['addurl', '--name', 'test-name']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='totp', label=None, secret='TEST',
        keychain=None, update=False)


@pytest.mark.parametrize('url', [
    'otpauth://totp/test-label?secret=TEST#fragment',
    'otpauth://totp/test-label?secret=TEST&secret=BLAH',
    'otpauth://totp/test-label?secret=TEST&ignored=whatever',
])
def test_addurl_extra_info(parser, mocks, mock_sys, url):
    mock_sys.stdin.read.return_value = url

    do_command(parser.parse_args(['addurl', '--name', 'test-name']))

    mocks.credential_manager.add_credential.assert_called_once_with(
        name='test-name', type_='totp', label='test-label', secret='TEST',
        keychain=None, update=False)


def test_getotp(parser, mocks, capsys):
    mocks.credential_manager.get_otp.return_value = '123456'

    do_command(parser.parse_args(['getotp', '--name', 'test-name']))

    assert capsys.readouterr().out == '123456\n'

    mocks.credential_manager.get_otp.assert_called_once_with('test-name')


def test_geturl(parser, mocks, capsys):
    url = 'otpauth://totp/test-name?secret=TEST'
    mocks.credential_manager.get_url.return_value = url

    do_command(parser.parse_args(['geturl', '--name', 'test-name']))

    assert capsys.readouterr().out == f'{url}\n'

    mocks.credential_manager.get_url.assert_called_once_with('test-name')


def test_delete(parser, mocks):
    do_command(parser.parse_args(['delete', '--name', 'test-name']))

    mocks.credential_manager.delete_credential.assert_called_once_with(
        'test-name', force=False)


def test_delete_force(parser, mocks):
    do_command(parser.parse_args(['delete', '--name', 'test-name', '--force']))

    mocks.credential_manager.delete_credential.assert_called_once_with(
        'test-name', force=True)


def test_list(parser, mocks, capsys):
    mocks.credential_manager.get_all_metadata.return_value = [
        CredentialMetadata(name='test1', type='totp', label=None, issuer=None,
                           algorithm=None, digits=None, period=None,
                           counter=None, keychain=None),
        CredentialMetadata(name='test2', type='hotp', label=None, issuer=None,
                           algorithm=None, digits=None, period=None, counter=0,
                           keychain=None),
    ]

    do_command(parser.parse_args(['list']))

    assert capsys.readouterr().out == 'test1\ntest2\n'

    mocks.credential_manager.get_all_metadata.assert_called_once_with()


def test_list_empty(parser, mocks, capsys):
    mocks.credential_manager.get_all_metadata.return_value = []

    do_command(parser.parse_args(['list']))

    assert capsys.readouterr().out == ''

    mocks.credential_manager.get_all_metadata.assert_called_once_with()


def test_list_table(parser, mocks, capsys):
    mocks.credential_manager.get_all_metadata.return_value = [
        CredentialMetadata(name='test1', type='totp', label=None, issuer=None,
                           algorithm=None, digits=None, period=None,
                           counter=None, keychain=None),
        CredentialMetadata(name='test2', type='hotp', label=None, issuer=None,
                           algorithm=None, digits=None, period=None, counter=0,
                           keychain=None),
        CredentialMetadata(name='test3', type='totp', label='label3',
                           issuer='issuer3', algorithm='SHA1', digits=7,
                           period=15, counter=None, keychain='test.keychain'),
    ]

    do_command(parser.parse_args(['list', '--table']))

    assert capsys.readouterr().out == \
        'Name\tType\tLabel\tIssuer\tAlgorithm\tDigits\tPeriod\tCounter\t' \
        'Keychain\n' \
        'test1\ttotp\t\t\t\t\t\t\t\n' \
        'test2\thotp\t\t\t\t\t\t0\t\n' \
        'test3\ttotp\tlabel3\tissuer3\tSHA1\t7\t15\t\ttest.keychain\n'

    mocks.credential_manager.get_all_metadata.assert_called_once_with()
