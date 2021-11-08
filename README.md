# twofa

A command-line tool for managing TOTP/HOTP credentials using the Mac OS
keychain.

## Usage

Use the `add` command to add a new credential. The secret can be passed into
stdin or provided interactively via a terminal prompt.

    python3 twofa.py add --name example --totp

You can use the `addurl` command to add a credential from a URL. This example
uses [ZBar](https://github.com/mchehab/zbar) to extract a URL from a QR code
and store the information using twofa:

    zbarimg qr.png | python3 twofa.py addurl --name url-example

The `getotp` command generates a one-time password for a credential:

    python3 twofa.py getotp --name example

To export a credential you can use the `geturl` command. This example generates
a QR code for a credential using
[libqrencode](https://fukuchi.org/works/qrencode/).

    python3 twofa.py geturl --name example | qrencode -o qr.png

For full command-line documentation, see `python3 twofa.py --help`.

## Configuration

You can set the following environment variables to configure twofa:

* `TWOFA_DB_PATH`: Path twofa's credential metadata database. The default
  location is `~/.twofa.sqlite3`
