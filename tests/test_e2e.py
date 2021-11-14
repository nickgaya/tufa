"""End-to-end tests of the twofa CLI."""

import os
import subprocess

import mintotp
import pytest

TEST_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET = 'ORSXG5BAMJ4XIZLT'


def _run(command, input=None):
    kwargs = {'input': input} if input else {'stdin': subprocess.DEVNULL}
    return subprocess.run(command, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, check=True,
                          **kwargs)


def _twofa(*args, input=None):
    twofa_command = ['python3', 'twofa.py', *args]
    return _run(twofa_command, input=input)


@pytest.fixture(scope='module', autouse=True)
def test_db():
    db_path = f'{TEST_DIR}/test.db'
    os.environ['TWOFA_DB_PATH'] = db_path
    yield db_path
    try:
        os.remove(db_path)
    except FileNotFoundError:
        pass


@pytest.fixture(scope='module', autouse=True)
def test_keychain():
    keychain_path = f'{TEST_DIR}/test.keychain'
    _run(['/usr/bin/security', 'create-keychain', '-p', 'test', keychain_path])
    os.environ['TWOFA_DEFAULT_KEYCHAIN'] = keychain_path
    yield keychain_path
    _run(['/usr/bin/security', 'delete-keychain', keychain_path])


def test_add_totp():
    _twofa('add', '--name', 'test1', '--totp', input=SECRET)

    result = _twofa('geturl', '--name', 'test1')
    assert result.stdout == f"otpauth://totp/test1?secret={SECRET}\n"

    totp_pre = mintotp.totp(SECRET)
    result = _twofa('getotp', '--name', 'test1')
    totp_post = mintotp.totp(SECRET)
    assert result.stdout.endswith('\n')
    otp = result.stdout[:-1]
    assert otp in (totp_pre, totp_post)


def test_add_hotp():
    _twofa('add', '--name', 'test2', '--hotp', input=SECRET)

    result = _twofa('geturl', '--name', 'test2')
    assert result.stdout == f"otpauth://hotp/test2?secret={SECRET}&counter=0\n"

    result = _twofa('getotp', '--name', 'test2')
    assert result.stdout == '106795\n'
    result = _twofa('getotp', '--name', 'test2')
    assert result.stdout == '376952\n'
