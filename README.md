# tufa

A command-line tool for managing TOTP/HOTP credentials using the Mac OS
keychain.

## Usage

Use the `add` command to add a new credential. The secret can be passed into
stdin or provided interactively via a terminal prompt.

    python3 tufa.py add --name example --totp

You can use the `addurl` command to add a credential from a URL. This example
uses [ZBar](https://github.com/mchehab/zbar) to extract a URL from a QR code
and store the information using tufa:

    zbarimg qr.png | python3 tufa.py addurl --name url-example

The `getotp` command generates a one-time password for a credential:

    python3 tufa.py getotp --name example

To export a credential you can use the `geturl` command. This example generates
a QR code for a credential using
[libqrencode](https://fukuchi.org/works/qrencode/).

    python3 tufa.py geturl --name example | qrencode -o qr.png

For full command-line documentation, see `python3 tufa.py --help`.

## Configuration

You can set the following environment variables to configure tufa:

* `TUFA_DB_PATH`: Path tufa's credential metadata database. The default
  location is `~/.tufa.sqlite3`
* `TUFA_DEFAULT_KEYCHAIN`: Keychain to use when adding credentials, if not
  specified via command-line flags.
