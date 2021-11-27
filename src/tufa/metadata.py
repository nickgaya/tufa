"""Metadata persistence layer."""

import sqlite3
from collections import namedtuple

CredentialMetadata = namedtuple(
    'CredentialMetadata', ('name', 'type', 'label', 'issuer', 'algorithm',
                           'digits', 'period', 'counter', 'keychain'))


class MetadataStore:
    """Class for storing and retrieving credential metadata."""

    def __init__(self, db_path):
        self.connection = sqlite3.connect(db_path)
        self._create_table()

    def _create_table(self):
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS tufa_metadata(
                name TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                label TEXT,
                issuer TEXT,
                algorithm TEXT,
                digits INTEGER,
                period INTEGER,
                counter INTEGER,
                keychain TEXT
            )
        """)

    def store_metadata(self, metadata, update=False):
        """Store metadata for the given credential."""
        operation = 'REPLACE' if update else 'INSERT'
        with self.connection:
            self.connection.execute(
                f"{operation} INTO tufa_metadata (name, type, label, issuer, "
                "algorithm, digits, period, counter, keychain) VALUES (?, ?, "
                "?, ?, ?, ?, ?, ?, ?)", metadata)

    def retrieve_metadata(self, name):
        """Retrieve metadata for the given credential."""
        row = self.connection.execute(
            "SELECT name, type, label, issuer, algorithm, digits, period, "
            "counter, keychain FROM tufa_metadata WHERE name = ?",
            (name,)).fetchone()
        return CredentialMetadata(*row) if row else None

    def retrieve_all_metadata(self):
        """Retrieve metadata for all credentials."""
        return [CredentialMetadata(*row) for row in self.connection.execute(
            "SELECT name, type, label, issuer, algorithm, digits, period, "
            "counter, keychain FROM tufa_metadata ORDER BY name")]

    def increment_hotp_counter(self, name):
        """Increment the counter for the given HOTP credential."""
        with self.connection:
            return self.connection.execute(
                "UPDATE tufa_metadata SET counter = counter + 1 "
                "WHERE name = ?", (name,)).rowcount

    def delete_metadata(self, name):
        """Delete metadata for the given credential."""
        with self.connection:
            return self.connection.execute(
                "DELETE FROM tufa_metadata WHERE name = ?", (name,)).rowcount

    def close(self):
        """Close the underlying db connection."""
        self.connection.close()
