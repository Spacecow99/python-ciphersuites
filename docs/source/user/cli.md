# Command line: python -m ciphersuites

The package has a small command line. It prints cipher suites from the
packaged data as {term}`JSON` text. Use it when you want the data in a shell
script or in a program that is not written in Python.

JSON (JavaScript Object Notation) is a text format for lists and
key-value objects. Most programming languages can read it.

This page documents `python -m ciphersuites`. The package also installs
the command `ciphersuites-scrape`. That command builds the data files
and is for maintainers; the
[developer guide](../developer/runner-and-cli.md) documents it.

## Run the command

Run the command with the Python of the environment where you installed
the package:

```console
$ python -m ciphersuites -V
0.1.0
```

`python -m ciphersuites` runs the package as a program. There is no
separate `ciphersuites` command.

## Options

| Option | Argument | Meaning |
|---|---|---|
| `-h`, `--help` | - | Print the help text and exit with code 0. |
| `-V`, `--package-version` | - | Print the version of the package and exit with code 0. |
| `--library` | a library name, for example `go` | Print only the suites of this library, from any of its versions. |
| `--version` | a version label, for example `1.12` | Print only the suites of this version of the library. Needs `--library`. |

Without options, the command prints every suite in the data.

`--version` is the version of the *library*, not of the package. The
package version option is `-V` or `--package-version`.

The help text:

```console
$ python -m ciphersuites --help
usage: ciphersuites [-h] [-V] [--library LIBRARY] [--version LABEL]

...
  -h, --help            show this help message and exit
  -V, --package-version
                        show the package version and exit
  --library LIBRARY     only suites of this library
  --version LABEL       only suites of this library version (requires
                        --library)
```

The line that the example hides with `...` is the title of the option
list. Its text depends on the Python version: `options:` or
`optional arguments:`.

### `--library`

The value must be one of the ten library names. `catalog.libraries()`
in Python lists them:
`boringssl`, `gnutls`, `go`, `jsse`, `libressl`, `mbedtls`, `nss`,
`openssl`, `s2n`, `schannel`.

The command prints every suite that at least one version of the library
contains, sorted by code point.

The names of the {term}`reference source`s (`iana`, `testssl`,
`scanigma`) do not work here. The Python API accepts them in some
functions, but the command line does not. See
[Exit codes](#exit-codes).

### `--version`

The value must be a version label of the library given with
`--library`. Labels are written exactly as in the data, for example `3.0`
for OpenSSL or `Windows 11` for Schannel. Put labels that contain spaces
in quotes:

```console
$ python -m ciphersuites --library schannel --version "Windows Vista" | python -c "import json, sys; print(len(json.load(sys.stdin)) > 0)"
True
```

To list the labels of a library, use `catalog.versions()` in Python (see
the [Python API reference](api.md#versions)), or see
[Versions and labels](../data/versions-and-labels.md).

For BoringSSL, the label is a date or a release tag. See
[Which BoringSSL label do I use?](faq.md#which-boringssl-label-do-i-use)

## Output

The command prints one JSON list. Each item is an object for one suite.
The list is sorted by {term}`code point`. Each object has these keys, in
this order:

| Key | JSON type | Meaning |
|---|---|---|
| `code_point` | list of strings | The code point, for example `["0xC0", "0x2F"]`. |
| `name` | string | The catalogue name. |
| `sources` | list of strings | The reference sources that list the code point. |
| `protocol` | string or null | `TLS` or `SSL`. |
| `key_exchange` | string or null | The key exchange algorithm. |
| `authentication` | string or null | The authentication algorithm. |
| `encryption` | string or null | The encryption algorithm. |
| `hashing` | string or null | The hash algorithm. |
| `old` | boolean or null | The name contains `OLD`. |
| `export` | boolean or null | The name contains `EXPORT`. Always `false` for SSLv2 suites, also the {term}`export-grade` ones; see `CipherSuite` in the [API reference](api.md#ciphersuite). |
| `fips` | boolean or null | The name contains `FIPS`. |
| `aead` | boolean or null | The encryption is an {term}`AEAD` mode. |

The keys have the same meaning as the attributes of `CipherSuite` with
the same name: see [`CipherSuite`](api.md#ciphersuite). For a
{term}`fallback suite`, `sources` is an empty list and the nine fields
from `protocol` to `aead` are `null`.

The output does not say which versions contain a suite, or which names
each library uses. Use the Python API for that.

This example prints the suites of Go 1.12. Only the start of the output
is shown:

```console
$ python -m ciphersuites --library go --version 1.12
[
  {
    "code_point": [
      "0x00",
      "0x05"
    ],
    "name": "TLS_RSA_WITH_RC4_128_SHA",
...
]
```

The output is indented with two spaces. This example prints the keys of
the first object:

```console
$ python -m ciphersuites --library go --version 1.12 | python -c "import json, sys; print(list(json.load(sys.stdin)[0]))"
['code_point', 'name', 'sources', 'protocol', 'key_exchange', 'authentication', 'encryption', 'hashing', 'old', 'export', 'fips', 'aead']
```

This example counts the suites of Go 1.12:

```console
$ python -m ciphersuites --library go --version 1.12 | python -c "import json, sys; print(len(json.load(sys.stdin)))"
26
```

## Exit codes

The {term}`exit code` is the number that a command returns to the shell. `0`
means success. In a POSIX shell, `$?` holds the exit code of the last
command.

| Exit code | When | Message (on standard error) |
|---|---|---|
| 0 | The suites were printed, or `-h` or `-V` was used. | - |
| 1 | The library name is unknown. | `unknown library: '<name>'` |
| 1 | The version label is unknown for that library. | `unknown version '<label>' of '<library>'` |
| 1 | The data cannot be loaded. | The message of `DataNotFoundError`. See [Errors](errors.md). |
| 2 | The options are wrong, for example `--version` without `--library`, or an unknown option. | A usage line and an error line. |
| 130 | You stopped the command with Ctrl+C. | - |

In the examples below, `2>&1` sends the error message to the normal
output, so that you can see it. `echo "exit=$?"` prints the exit code.

An unknown library:

```console
$ python -m ciphersuites --library nosuchlib 2>&1; echo "exit=$?"
unknown library: 'nosuchlib'
exit=1
```

A reference source is not a library here:

```console
$ python -m ciphersuites --library iana 2>&1; echo "exit=$?"
unknown library: 'iana'
exit=1
```

An unknown version:

```console
$ python -m ciphersuites --library go --version 9.9 2>&1; echo "exit=$?"
unknown version '9.9' of 'go'
exit=1
```

`--version` without `--library`:

```console
$ python -m ciphersuites --version 1.12 2>&1; echo "exit=$?"
usage: ciphersuites [-h] [-V] [--library LIBRARY] [--version LABEL]
ciphersuites: error: --version requires --library
exit=2
```

An unknown option:

```console
$ python -m ciphersuites --nosuchoption 2>&1; echo "exit=$?"
usage: ciphersuites [-h] [-V] [--library LIBRARY] [--version LABEL]
ciphersuites: error: unrecognized arguments: --nosuchoption
exit=2
```

Exit code 1 for missing data and exit code 130 for Ctrl+C have no
example here, because the tests cannot remove the data or press
Ctrl+C. The [install page](install.md#if-you-cloned-without-the-submodule)
shows the message for missing data.
