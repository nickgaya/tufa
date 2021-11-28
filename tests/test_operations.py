"""Tests of tufa.operations."""

from unittest import mock

import pytest

from tufa.exceptions import (
    CredentialExistsError,
    CredentialNotFoundError,
    KeychainError,
)
from tufa.metadata import CredentialMetadata, MetadataStore
from tufa.operations import CredentialManager
from tufa.secrets import SecretStore

NAME = mock.sentinel.name
TYPE = mock.sentinel.type
SECRET = mock.sentinel.secret
LABEL = mock.sentinel.label
ISSUER = mock.sentinel.issuer
ALGORITHM = mock.sentinel.algorithm
DIGITS = mock.sentinel.digits
PERIOD = mock.sentinel.period
COUNTER = mock.sentinel.counter
KEYCHAIN = mock.sentinel.keychain


@pytest.fixture(autouse=True)
def mock_os(mocker):
    return mocker.patch('tufa.operations.os', autospec=True)


@pytest.fixture(autouse=True)
def mock_otp(mocker):
    mock_get_hotp = mocker.patch('tufa.operations.get_hotp', autospec=True)
    mock_get_totp = mocker.patch('tufa.operations.get_totp', autospec=True)
    mock_otp = mock.MagicMock(name='otp')
    mock_otp.attach_mock(mock_get_hotp, 'get_hotp')
    mock_otp.attach_mock(mock_get_totp, 'get_totp')
    return mock_otp


@pytest.fixture
def mocks(mock_os, mock_otp):
    # Use a top-level mock object so we can verify the relative order of calls
    # to the secret and metadata stores
    mocks = mock.MagicMock(name='mocks')
    mocks.secret_store.configure_mock(spec=SecretStore)
    mocks.metadata_store.configure_mock(spec=MetadataStore)
    mocks.attach_mock(mock_os, 'os')
    mocks.attach_mock(mock_otp, 'otp')
    return mocks


@pytest.fixture
def credential_manager(mocks):
    return CredentialManager(mocks.secret_store, mocks.metadata_store)


def test_add_credential(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = None

    credential_manager.add_credential(NAME, TYPE, SECRET)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.store_secret(NAME, SECRET, None, False),
        mock.call.metadata_store.store_metadata(CredentialMetadata(
            name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
            digits=None, period=None, counter=None, keychain=None),
            update=False),
    ]


def test_add_credential_params(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = None

    credential_manager.add_credential(
        NAME, TYPE, SECRET,
        label=LABEL, issuer=ISSUER, algorithm=ALGORITHM, digits=DIGITS,
        period=PERIOD, counter=COUNTER, keychain=KEYCHAIN)

    assert mocks.mock_calls == [
        mock.call.secret_store.verify_keychain(KEYCHAIN),
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.store_secret(NAME, SECRET, KEYCHAIN, False),
        mock.call.metadata_store.store_metadata(CredentialMetadata(
            name=NAME, type=TYPE, label=LABEL, issuer=ISSUER,
            algorithm=ALGORITHM, digits=DIGITS, period=PERIOD, counter=COUNTER,
            keychain=KEYCHAIN), update=False),
    ]


def test_add_credential_exists(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=None)

    with pytest.raises(CredentialExistsError):
        credential_manager.add_credential(NAME, TYPE, SECRET)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
    ]


def test_add_credential_update(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type=mock.sentinel.old_type, label=None, issuer=None,
        algorithm=None, digits=None, period=None, counter=None, keychain=None)

    credential_manager.add_credential(NAME, TYPE, SECRET, update=True)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.store_secret(NAME, SECRET, None, True),
        mock.call.metadata_store.store_metadata(CredentialMetadata(
            name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
            digits=None, period=None, counter=None, keychain=None),
            update=True),
    ]


def test_add_credential_update_keychain(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=KEYCHAIN)

    credential_manager.add_credential(NAME, TYPE, SECRET, update=True)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.delete_secret(NAME, KEYCHAIN),
        mock.call.secret_store.store_secret(NAME, SECRET, None, True),
        mock.call.metadata_store.store_metadata(CredentialMetadata(
            name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
            digits=None, period=None, counter=None, keychain=None),
            update=True),
    ]


def test_add_credential_verify_error(credential_manager, mocks):
    mocks.secret_store.verify_keychain.side_effect = KeychainError("test")

    with pytest.raises(KeychainError):
        credential_manager.add_credential(NAME, TYPE, SECRET,
                                          keychain='example.keychain')

    assert mocks.mock_calls == [
        mock.call.secret_store.verify_keychain('example.keychain'),
    ]


def test_add_credential_verify_error_suggestion(credential_manager, mocks):
    mocks.secret_store.verify_keychain.side_effect = KeychainError("test")
    mocks.os.path.exists.return_value = True

    with pytest.raises(KeychainError) as excinfo:
        credential_manager.add_credential(NAME, TYPE, SECRET,
                                          keychain='example')

    assert excinfo.value.info == 'Try --keychain example.keychain'

    assert mocks.mock_calls == [
        mock.call.secret_store.verify_keychain('example'),
        mock.call.os.path.expanduser(
            '~/Library/Keychains/example.keychain-db'),
        mock.call.os.path.exists(mocks.os.path.expanduser.return_value),
    ]


def test_get_otp_totp(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type='totp', label=LABEL, issuer=ISSUER,
        algorithm=ALGORITHM, digits=DIGITS, period=PERIOD, counter=None,
        keychain=KEYCHAIN)
    mocks.secret_store.retrieve_secret.return_value = SECRET

    assert credential_manager.get_otp(NAME) is mocks.otp.get_totp.return_value

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.retrieve_secret(NAME, keychain=KEYCHAIN),
        mock.call.otp.get_totp(SECRET, PERIOD, ALGORITHM, DIGITS),
    ]


def test_get_otp_hotp(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type='hotp', label=LABEL, issuer=ISSUER,
        algorithm=ALGORITHM, digits=DIGITS, period=None, counter=COUNTER,
        keychain=KEYCHAIN)
    mocks.secret_store.retrieve_secret.return_value = SECRET

    assert credential_manager.get_otp(NAME) is mocks.otp.get_hotp.return_value

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.retrieve_secret(NAME, keychain=KEYCHAIN),
        mock.call.otp.get_hotp(SECRET, COUNTER, ALGORITHM, DIGITS),
        mock.call.metadata_store.increment_hotp_counter(NAME),
    ]


def test_get_otp_not_found(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = None

    with pytest.raises(CredentialNotFoundError):
        credential_manager.get_otp(NAME)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
    ]


def test_get_url_totp(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name='example', type='totp', label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=KEYCHAIN)
    mocks.secret_store.retrieve_secret.return_value = 'TEST'

    assert credential_manager.get_url('example') == \
        'otpauth://totp/example?secret=TEST'

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata('example'),
        mock.call.secret_store.retrieve_secret('example', keychain=KEYCHAIN),
    ]


def test_get_url_totp_params(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name='example', type='totp', label='label', issuer='issuer',
        algorithm='SHA512', digits=8, period=60, counter=None,
        keychain=KEYCHAIN)
    mocks.secret_store.retrieve_secret.return_value = 'TEST'

    assert credential_manager.get_url('example') == \
        'otpauth://totp/label?secret=TEST&issuer=issuer&algorithm=SHA512' \
        '&digits=8&period=60'

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata('example'),
        mock.call.secret_store.retrieve_secret('example', keychain=KEYCHAIN),
    ]


def test_get_url_hotp(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name='example', type='hotp', label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=0, keychain=KEYCHAIN)
    mocks.secret_store.retrieve_secret.return_value = 'TEST'

    assert credential_manager.get_url('example') == \
        'otpauth://hotp/example?secret=TEST&counter=0'

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata('example'),
        mock.call.secret_store.retrieve_secret('example', keychain=KEYCHAIN),
    ]


def test_get_url_hotp_params(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name='example', type='hotp', label='label', issuer='issuer',
        algorithm='SHA256', digits=8, period=None, counter=12,
        keychain=KEYCHAIN)
    mocks.secret_store.retrieve_secret.return_value = 'TEST'

    assert credential_manager.get_url('example') == \
        'otpauth://hotp/label?secret=TEST&issuer=issuer&algorithm=SHA256' \
        '&digits=8&counter=12'

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata('example'),
        mock.call.secret_store.retrieve_secret('example', keychain=KEYCHAIN),
    ]


def test_get_url_not_found(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = None

    with pytest.raises(CredentialNotFoundError):
        credential_manager.get_url(NAME)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
    ]


def test_delete_credential(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=KEYCHAIN)

    credential_manager.delete_credential(NAME)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.delete_secret(NAME, keychain=KEYCHAIN),
        mock.call.metadata_store.delete_metadata(NAME),
    ]


def test_delete_credential_not_found(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = None

    with pytest.raises(CredentialNotFoundError):
        credential_manager.delete_credential(NAME)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
    ]


def test_delete_credential_keychain_error(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=KEYCHAIN)
    mocks.secret_store.delete_secret.side_effect = KeychainError("test")

    with pytest.raises(KeychainError):
        credential_manager.delete_credential(NAME)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.delete_secret(NAME, keychain=KEYCHAIN),
    ]


def test_delete_credential_keychain_error_force(credential_manager, mocks):
    mocks.metadata_store.retrieve_metadata.return_value = CredentialMetadata(
        name=NAME, type=TYPE, label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=KEYCHAIN)
    mocks.secret_store.delete_secret.side_effect = KeychainError("test")

    credential_manager.delete_credential(NAME, force=True)

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_metadata(NAME),
        mock.call.secret_store.delete_secret(NAME, keychain=KEYCHAIN),
        mock.call.metadata_store.delete_metadata(NAME),
    ]


def test_get_all_metadata(credential_manager, mocks):
    assert credential_manager.get_all_metadata() is \
        mocks.metadata_store.retrieve_all_metadata.return_value

    assert mocks.mock_calls == [
        mock.call.metadata_store.retrieve_all_metadata(),
    ]
