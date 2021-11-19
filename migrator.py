"""Migration script for project rename from twofa to tufa."""

import argparse
import logging
import os.path
import sqlite3

import tufa

logger = logging.getLogger('migrator')


def relocate_db(path):
    if path:
        return path

    old_path = os.path.expanduser('~/.twofa.sqlite3')
    new_path = os.path.expanduser('~/.tufa.sqlite3')

    if os.path.exists(old_path):
        logger.info("Renaming %s to %s", old_path, new_path)
        if os.path.exists(new_path):
            raise FileExistsError(new_path)
        os.rename(old_path, new_path)

    return new_path


def rename_metadata_table(db_path):
    connection = sqlite3.connect(db_path)
    old_table_exists, = connection.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type = 'table' AND name = 'twofa_metadata'").fetchone()
    if old_table_exists:
        logger.info("Renaming metadata db table")
        connection.execute(
            "ALTER TABLE twofa_metadata RENAME TO tufa_metadata")
    connection.close()


def migrate_secrets(db_path):
    metadata_store = tufa.MetadataStore(db_path)
    old_secret_store = tufa.SecretStore('twofa')
    new_secret_store = tufa.SecretStore()
    for metadata in metadata_store.retrieve_all_metadata():
        logger.info("Migrating credential %r", metadata.name)
        try:
            secret = old_secret_store.retrieve_secret(
                metadata.name, keychain=metadata.keychain)
            new_secret_store.store_secret(
                metadata.name, secret, keychain=metadata.keychain)
            old_secret_store.delete_secret(
                metadata.name, keychain=metadata.keychain)
        except tufa.KeychainError as e:
            logger.warning(
                "%s", e, exc_info=logger.isEnabledFor(logging.DEBUG))


def main():
    parser = argparse.ArgumentParser(
        description="Tufa name change migration script")
    parser.add_argument('--debug', '-d', action='store_true', help="Enable "
                        "debug logging")
    parser.add_argument('--db-path', '-p', help="Path to the metadata db file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    if args.debug:
        tufa.logger.setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    # If using default path, rename to new default location
    db_path = relocate_db(args.db_path)
    # Rename metadata table in db
    rename_metadata_table(db_path)
    # Migrate secrets in keychain
    migrate_secrets(db_path)
    logger.info("Success")


if __name__ == '__main__':
    main()
