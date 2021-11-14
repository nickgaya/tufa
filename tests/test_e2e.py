"""End-to-end tests of the twofa CLI."""

import os
import sys
import subprocess

import mintotp
import pytest

TEST_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET = 'ORSXG5BAMJ4XIZLT'
SECRET_2 = 'BJVNQY3PK2BG2UF6'

CREDENTIAL_EXISTS_RC = 2
CREDENTIAL_NOT_FOUND_RC = 3
KEYCHAIN_ERROR_RC = 4


def _run(command, input=None):
    kwargs = {'input': input} if input else {'stdin': subprocess.DEVNULL}
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    print(result.stderr, end='', file=sys.stderr, flush=True)
    result.check_returncode()
    return result


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


@pytest.fixture
def name(request):
    return request.node.name


def test_add_totp(name):
    _twofa('add', '--name', name, '--totp', input=SECRET)

    result = _twofa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET}\n"

    totp_pre = mintotp.totp(SECRET)
    result = _twofa('getotp', '--name', name)
    totp_post = mintotp.totp(SECRET)
    assert result.stdout.endswith('\n')
    otp = result.stdout[:-1]
    assert otp in (totp_pre, totp_post)

    _twofa('delete', '--name', name)


def test_add_hotp(name):
    _twofa('add', '--name', name, '--hotp', input=SECRET)

    result = _twofa('geturl', '--name', name)
    assert result.stdout == \
        f"otpauth://hotp/{name}?secret={SECRET}&counter=0\n"

    result = _twofa('getotp', '--name', name)
    assert result.stdout == '106795\n'
    result = _twofa('getotp', '--name', name)
    assert result.stdout == '376952\n'

    _twofa('delete', '--name', name)


def test_add_update(name):
    _twofa('add', '--name', name, '--totp', input=SECRET)

    result = _twofa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET}\n"

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('add', '--name', name, '--totp', input=SECRET_2)
    assert exc_info.value.returncode == CREDENTIAL_EXISTS_RC

    result = _twofa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET}\n"

    _twofa('add', '--name', name, '--totp', '--update', input=SECRET_2)

    result = _twofa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET_2}\n"

    _twofa('delete', '--name', name)


def test_add_invalid_keychain(name):
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('add', '--name', name, '--totp',
               '--keychain', f'{TEST_DIR}/invalid.keychain', input=SECRET)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    # Verify credential not in db
    assert name not in _twofa('list').stdout.splitlines()


def test_addurl(name):
    url = f"otpauth://hotp/label?secret={SECRET}&counter=123"
    _twofa('addurl', '-n', name, input=url)

    result = _twofa('geturl', '--name', name)
    assert result.stdout == f'{url}\n'

    result = _twofa('getotp', '--name', name)
    assert result.stdout == '016128\n'
    result = _twofa('getotp', '--name', name)
    assert result.stdout == '738649\n'

    _twofa('delete', '--name', name)


def test_get_nonexistent(name):
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('getotp', '--name', name)
    assert exc_info.value.returncode == CREDENTIAL_NOT_FOUND_RC

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('geturl', '--name', name)
    assert exc_info.value.returncode == CREDENTIAL_NOT_FOUND_RC


def test_get_keychain_error(test_keychain, name):
    _twofa('add', '--name', name, '--totp', input=SECRET)
    _run(['/usr/bin/security', 'delete-generic-password',
          '-s', 'twofa', '-a', name, test_keychain])

    assert name in _twofa('list').stdout.splitlines()

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('getotp', '--name', name)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('geturl', '--name', name)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    _twofa('delete', '--name', name, '--force')


def test_delete_nonexistent(name):
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('delete', '--name', name)
    assert exc_info.value.returncode == CREDENTIAL_NOT_FOUND_RC


def test_delete_force(test_keychain, name):
    _twofa('add', '--name', name, '--totp', input=SECRET)
    _run(['/usr/bin/security', 'delete-generic-password',
          '-s', 'twofa', '-a', name, test_keychain])

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _twofa('delete', '--name', name)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    _twofa('delete', '--name', name, '--force')

    assert name not in _twofa('list').stdout.splitlines()


def test_list(name):
    assert _twofa('list').stdout == ''

    name1 = f'{name}-T'
    name2 = f'{name}-H'

    _twofa('add', '--name', name1, '--totp', input=SECRET)
    _twofa('add', '--name', name2, '--hotp', input=SECRET_2)

    # List should be sorted alphabetically
    assert _twofa('list').stdout.splitlines() == [name2, name1]

    _twofa('delete', '--name', name1)
    _twofa('delete', '--name', name2)

    assert _twofa('list').stdout == ''
