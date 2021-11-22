"""End-to-end tests of the tufa CLI."""

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


def _tufa(*args, input=None):
    tufa_command = ['tufa', *args]
    return _run(tufa_command, input=input)


@pytest.fixture(scope='module', autouse=True)
def test_db():
    db_path = f'{TEST_DIR}/test.db'
    os.environ['TUFA_DB_PATH'] = db_path
    yield db_path
    try:
        os.remove(db_path)
    except FileNotFoundError:
        pass


@pytest.fixture(scope='module', autouse=True)
def test_keychain():
    keychain_path = f'{TEST_DIR}/test.keychain'
    _run(['/usr/bin/security', 'create-keychain', '-p', 'test', keychain_path])
    os.environ['TUFA_DEFAULT_KEYCHAIN'] = keychain_path
    yield keychain_path
    _run(['/usr/bin/security', 'delete-keychain', keychain_path])


@pytest.fixture
def name(request):
    return request.node.name


def test_add_totp(name):
    _tufa('add', '--name', name, '--totp', input=SECRET)

    result = _tufa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET}\n"

    totp_pre = mintotp.totp(SECRET)
    result = _tufa('getotp', '--name', name)
    totp_post = mintotp.totp(SECRET)
    assert result.stdout.endswith('\n')
    otp = result.stdout[:-1]
    assert otp in (totp_pre, totp_post)

    _tufa('delete', '--name', name)


def test_add_hotp(name):
    _tufa('add', '--name', name, '--hotp', input=SECRET)

    result = _tufa('geturl', '--name', name)
    assert result.stdout == \
        f"otpauth://hotp/{name}?secret={SECRET}&counter=0\n"

    result = _tufa('getotp', '--name', name)
    assert result.stdout == '106795\n'
    result = _tufa('getotp', '--name', name)
    assert result.stdout == '376952\n'

    _tufa('delete', '--name', name)


def test_add_update(name):
    _tufa('add', '--name', name, '--totp', input=SECRET)

    result = _tufa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET}\n"

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('add', '--name', name, '--totp', input=SECRET_2)
    assert exc_info.value.returncode == CREDENTIAL_EXISTS_RC

    result = _tufa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET}\n"

    _tufa('add', '--name', name, '--totp', '--update', input=SECRET_2)

    result = _tufa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET_2}\n"

    _tufa('delete', '--name', name)


def test_add_invalid_keychain(name):
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('add', '--name', name, '--totp',
              '--keychain', f'{TEST_DIR}/invalid.keychain', input=SECRET)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    # Verify credential not in db
    assert name not in _tufa('list').stdout.splitlines()


def test_add_keychain_error(test_keychain, name):
    _run(['/usr/bin/security', 'add-generic-password',
          '-s', 'tufa', '-a', name, '-w', SECRET, test_keychain])

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('add', '--name', name, '--totp', input=SECRET_2)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    assert name not in _tufa('list').stdout.splitlines()

    _tufa('add', '--name', name, '--totp', '--update', input=SECRET_2)

    result = _tufa('geturl', '--name', name)
    assert result.stdout == f"otpauth://totp/{name}?secret={SECRET_2}\n"

    _tufa('delete', '--name', name)


def test_addurl(name):
    url = f"otpauth://hotp/label?secret={SECRET}&counter=123"
    _tufa('addurl', '-n', name, input=url)

    result = _tufa('geturl', '--name', name)
    assert result.stdout == f'{url}\n'

    result = _tufa('getotp', '--name', name)
    assert result.stdout == '016128\n'
    result = _tufa('getotp', '--name', name)
    assert result.stdout == '738649\n'

    _tufa('delete', '--name', name)


def test_get_nonexistent(name):
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('getotp', '--name', name)
    assert exc_info.value.returncode == CREDENTIAL_NOT_FOUND_RC

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('geturl', '--name', name)
    assert exc_info.value.returncode == CREDENTIAL_NOT_FOUND_RC


def test_get_keychain_error(test_keychain, name):
    _tufa('add', '--name', name, '--totp', input=SECRET)
    _run(['/usr/bin/security', 'delete-generic-password',
          '-s', 'tufa', '-a', name, test_keychain])

    assert name in _tufa('list').stdout.splitlines()

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('getotp', '--name', name)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('geturl', '--name', name)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    _tufa('delete', '--name', name, '--force')


def test_delete_nonexistent(name):
    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('delete', '--name', name)
    assert exc_info.value.returncode == CREDENTIAL_NOT_FOUND_RC


def test_delete_force(test_keychain, name):
    _tufa('add', '--name', name, '--totp', input=SECRET)
    _run(['/usr/bin/security', 'delete-generic-password',
          '-s', 'tufa', '-a', name, test_keychain])

    with pytest.raises(subprocess.CalledProcessError) as exc_info:
        _tufa('delete', '--name', name)
    assert exc_info.value.returncode == KEYCHAIN_ERROR_RC

    _tufa('delete', '--name', name, '--force')

    assert name not in _tufa('list').stdout.splitlines()


def test_list(name):
    assert _tufa('list').stdout == ''

    name1 = f'{name}-T'
    name2 = f'{name}-H'

    _tufa('add', '--name', name1, '--totp', input=SECRET)
    _tufa('add', '--name', name2, '--hotp', input=SECRET_2)

    # List should be sorted alphabetically
    assert _tufa('list').stdout.splitlines() == [name2, name1]

    _tufa('delete', '--name', name1)
    _tufa('delete', '--name', name2)

    assert _tufa('list').stdout == ''
