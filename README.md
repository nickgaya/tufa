# tufa

A command-line tool for managing TOTP/HOTP credentials using the Mac OS
keychain.

## Installation

Use pip to install the package in your desired environment:

    pip install -U .

## Usage

Use the `add` command to add a new credential. The secret can be passed into
stdin or provided interactively via a terminal prompt.

    tufa add --name example --totp

You can use the `addurl` command to add a credential from a URL. This example
uses [ZBar](https://github.com/mchehab/zbar) to extract a URL from a QR code
and store the information using tufa:

    zbarimg qr.png | tufa addurl --name example

The `getotp` command generates a one-time password for a credential:

    tufa getotp --name example

To export a credential you can use the `geturl` command. This example generates
a QR code for a credential using
[libqrencode](https://fukuchi.org/works/qrencode/).

    tufa geturl --name example | qrencode -o qr.png

For full command-line documentation, see `tufa --help`.

## Configuration

You can set the following environment variables to configure tufa:

* `TUFA_DB_PATH`: Path tufa's credential metadata database. The default
  location is `~/.tufa.sqlite3`
* `TUFA_DEFAULT_KEYCHAIN`: Keychain to use when adding credentials, if not
  specified via command-line flags.
