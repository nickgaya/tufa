"""Tests of tufa.secrets"""
from subprocess import CompletedProcess

import pytest

from tufa.exceptions import KeychainError
from tufa.secrets import SecretStore

NAME = 'test'
SECRET = 'GMTBYHBJGDL5BBO2'


@pytest.fixture(autouse=True)
def mock_subprocess(mocker):
    return mocker.patch('tufa.secrets.subprocess', autospec=True)


@pytest.fixture
def secret_store():
    return SecretStore()


def test_store_secret(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(args=..., returncode=0)
    secret_store.store_secret('test', SECRET)

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'add-generic-password',
         '-s', 'tufa', '-a', 'test',
         '-l', 'tufa: test',
         '-D', 'hotp/totp secret',
         '-w', SECRET],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_store_secret_update(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(args=..., returncode=0)
    secret_store.store_secret('test', SECRET, update=True)

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'add-generic-password',
         '-s', 'tufa', '-a', 'test',
         '-l', 'tufa: test',
         '-D', 'hotp/totp secret',
         '-w', SECRET,
         '-U'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_store_secret_keychain(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(args=..., returncode=0)
    secret_store.store_secret('test', SECRET, keychain='example.keychain')

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'add-generic-password',
         '-s', 'tufa', '-a', 'test',
         '-l', 'tufa: test',
         '-D', 'hotp/totp secret',
         '-w', SECRET,
         'example.keychain'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_store_secret_error(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(
        args=..., returncode=45)
    with pytest.raises(KeychainError):
        secret_store.store_secret('test', SECRET)

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'add-generic-password',
         '-s', 'tufa', '-a', 'test',
         '-l', 'tufa: test',
         '-D', 'hotp/totp secret',
         '-w', SECRET],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_retrieve_secret(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(
        args=..., returncode=0, stdout=SECRET)

    assert secret_store.retrieve_secret('test') == SECRET

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'find-generic-password',
         '-s', 'tufa', '-a', 'test', '-w'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_retrieve_secret_keychain(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(
        args=..., returncode=0, stdout=SECRET)

    assert secret_store.retrieve_secret('test', keychain='example.keychain') \
        == SECRET

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'find-generic-password',
         '-s', 'tufa', '-a', 'test', '-w', 'example.keychain'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_retrieve_secret_error(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(
        args=..., returncode=44)

    with pytest.raises(KeychainError):
        secret_store.retrieve_secret('test')

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'find-generic-password',
         '-s', 'tufa', '-a', 'test', '-w'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_delete_secret(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(args=..., returncode=0)

    secret_store.delete_secret('test')

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'delete-generic-password',
         '-s', 'tufa', '-a', 'test'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_delete_secret_keychain(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(args=..., returncode=0)

    secret_store.delete_secret('test', keychain='example.keychain')

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'delete-generic-password',
         '-s', 'tufa', '-a', 'test', 'example.keychain'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_delete_secret_error(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(
        args=..., returncode=44)

    with pytest.raises(KeychainError):
        secret_store.delete_secret('test')

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'delete-generic-password',
         '-s', 'tufa', '-a', 'test'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_verify_keychain(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(args=..., returncode=0)

    secret_store.verify_keychain('example.keychain')

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'show-keychain-info', 'example.keychain'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)


def test_verify_keychain_error(secret_store, mock_subprocess):
    mock_subprocess.run.return_value = CompletedProcess(
        args=..., returncode=50)

    with pytest.raises(KeychainError):
        secret_store.verify_keychain('example.keychain')

    mock_subprocess.run.assert_called_once_with(
        ['/usr/bin/security', 'show-keychain-info', 'example.keychain'],
        stdin=mock_subprocess.DEVNULL,
        capture_output=True, text=True, start_new_session=True)
