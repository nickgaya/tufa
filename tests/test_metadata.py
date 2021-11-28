"""Tests of tufa.metadata."""

import contextlib
import sqlite3

import pytest

from tufa.metadata import CredentialMetadata, MetadataStore

_fields = ', '.join(CredentialMetadata._fields)
_qmarks = ', '.join('?' for _ in CredentialMetadata._fields)


@pytest.fixture
def db_path(tmpdir):
    return str(tmpdir / 'test.db')


@pytest.fixture
def connection(db_path):
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        yield conn


@pytest.fixture
def metadata_store(db_path):
    with contextlib.closing(MetadataStore(db_path)) as metadata_store:
        yield metadata_store


def _add_rows(connection, *rows):
    for row in rows:
        connection.execute(
            f'INSERT INTO tufa_metadata ({_fields}) VALUES ({_qmarks})', row)
    connection.commit()


def _get_all(connection):
    return connection.execute(
        f'SELECT {_fields} FROM tufa_metadata').fetchall()


def test_store_metadata(metadata_store, connection):
    metadata = CredentialMetadata(
        name='test-name', type='test-type', label='test-label',
        issuer='test-issuer', algorithm='algorithm', digits=6, period=30,
        counter=10, keychain='example.keychain')
    metadata_store.store_metadata(metadata)

    assert _get_all(connection) == [metadata]


def test_store_metadata_update(metadata_store, connection):
    metadata1 = CredentialMetadata(
        name='example', type='totp', label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=None)
    metadata2 = CredentialMetadata(
        name='example', type='hotp', label='label', issuer='issuer',
        algorithm='algorithm', digits=8, period=None, counter=0,
        keychain='example.keychain')

    metadata_store.store_metadata(metadata1)
    metadata_store.store_metadata(metadata2, update=True)

    assert _get_all(connection) == [metadata2]


def test_retrieve_metadata(metadata_store, connection):
    metadata = CredentialMetadata(
        name='test-name', type='test-type', label='test-label',
        issuer='test-issuer', algorithm='algorithm', digits=6, period=30,
        counter=10, keychain='example.keychain')

    _add_rows(connection, metadata)

    assert metadata_store.retrieve_metadata('test-name') == metadata


def test_retrieve_metadata_none(metadata_store):
    assert metadata_store.retrieve_metadata('test-name') is None


def test_retrieve_all_metadata(metadata_store, connection):
    metadata1 = CredentialMetadata(
        name='exampleA', type='totp', label=None, issuer=None, algorithm=None,
        digits=None, period=None, counter=None, keychain=None)
    metadata2 = CredentialMetadata(
        name='exampleC', type='totp', label='labelC', issuer='issuerC',
        algorithm='SHA1', digits=6, period=30, counter=None, keychain=None)
    metadata3 = CredentialMetadata(
        name='exampleB', type='hotp', label='labelB', issuer='issuerB',
        algorithm='SHA512', digits=8, period=None, counter=10,
        keychain='example.keychain')

    _add_rows(connection, metadata1, metadata2, metadata3)

    assert metadata_store.retrieve_all_metadata() == \
        [metadata1, metadata3, metadata2]


def test_retrieve_all_metadata_empty(metadata_store):
    assert metadata_store.retrieve_all_metadata() == []


def test_increment_hotp_counter(metadata_store, connection):
    metadata = CredentialMetadata(
        name='example', type='hotp', label='label', issuer='issuer',
        algorithm='SHA1', digits=6, period=None, counter=5,
        keychain='example.keychain')

    _add_rows(connection, metadata)

    assert metadata_store.increment_hotp_counter('example') == 1

    assert _get_all(connection) == [metadata._replace(counter=6)]


def test_increment_hotp_counter_not_found(metadata_store):
    assert metadata_store.increment_hotp_counter('example') == 0


def test_delete_metadata(metadata_store, connection):
    metadata = CredentialMetadata(
        name='test-name', type='test-type', label='test-label',
        issuer='test-issuer', algorithm='algorithm', digits=6, period=30,
        counter=10, keychain='example.keychain')

    _add_rows(connection, metadata)

    assert metadata_store.delete_metadata('test-name') == 1

    assert _get_all(connection) == []


def test_delete_metadata_not_found(metadata_store):
    assert metadata_store.delete_metadata('test-name') == 0
