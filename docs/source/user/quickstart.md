# Quickstart

This page shows the most common queries, in a few minutes. It uses the
data that comes with the package. Install the package first: see
[Install the package](install.md).

Each example below is a Python session. Lines that start with `>>>` or
`...` are what you type. The other lines are what Python prints. You can
start a session with the command `python`.

## Get a suite by its code point

A {term}`code point` identifies a cipher suite. It is the same in every
library. So a lookup by code point always finds at most one suite.

```pycon
>>> from ciphersuites import catalog
>>> suite = catalog.get((0xC0, 0x2F))
>>> suite.name
'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
>>> suite.code_point
('0xC0', '0x2F')
```

You can write the code point with integers, as above, or with hex
strings such as `("0xC0", "0x2F")`. The package always gives it back as
a tuple of strings in the form `0xAB`.

The `name` is the {term}`catalogue` name. For most suites this is the
name in the {term}`IANA` registry.

The first query reads the data files. Later queries in the same program
reuse the loaded data.

## Read the parts of a suite

A suite object also tells you the algorithms that the suite uses:

```pycon
>>> from ciphersuites import catalog
>>> suite = catalog.get((0xC0, 0x2F))
>>> suite.protocol, suite.key_exchange, suite.authentication
('TLS', 'ECDHE', 'RSA')
>>> suite.encryption, suite.hashing, suite.aead
('AES 128 GCM', 'SHA256', True)
```

The package derives these values from the name. See
[The derived fields](../data/catalogue-schema.md#the-derived-fields) for
their limits.

## See which versions of a library contain a suite

Every method in this section takes a {term}`library` name, for example
`"openssl"` or `"go"`.

```pycon
>>> from ciphersuites import catalog
>>> suite = catalog.get((0xC0, 0x2F))
>>> suite.first_seen("openssl")
'1.0.2'
>>> suite.first_seen("go")
'1.12'
>>> suite.supported_in("openssl")[:3]
['1.0.2', '1.1.0', '1.1.1']
```

`first_seen` gives the oldest version in the data that contains the
suite. It is not always the version that added the suite: the data
starts at a minimum version for each library. For OpenSSL that is
`1.0.2`.

## See the names that a library uses

Libraries often use their own names. `names` maps each name to the
versions that use it:

```pycon
>>> from ciphersuites import catalog
>>> suite = catalog.get((0x00, 0x05))
>>> suite.name
'TLS_RSA_WITH_RC4_128_SHA'
>>> list(suite.names("boringssl"))
['RC4-SHA']
>>> suite.last_seen("boringssl")
'2016-06-02'
```

In the BoringSSL data, the last version that contains this RC4 suite is
the dated label `2016-06-02`. The next dated label, `2016-08-26`, does
not contain it.

## Get a suite by its name

You can also look up a suite by any name: the catalogue name, or a name
that a library uses.

```pycon
>>> from ciphersuites import catalog
>>> catalog.get("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").code_point
('0xC0', '0x2F')
>>> catalog.get("ECDHE-RSA-AES128-GCM-SHA256", library="openssl", version="1.0.2").code_point
('0xC0', '0x2F')
```

A name can belong to more than one code point. Then `get` raises
`AmbiguousNameError`. Read [Find a suite by name](name-resolution.md)
before you look up suites by name in a program.

## List the suites of one library version

```pycon
>>> from ciphersuites import catalog
>>> suites = catalog.supported_by("go", "1.12")
>>> len(suites)
26
>>> suites[0].code_point, suites[0].name
(('0x00', '0x05'), 'TLS_RSA_WITH_RC4_128_SHA')
```

## List libraries and versions

```pycon
>>> from ciphersuites import catalog
>>> catalog.libraries()
['boringssl', 'gnutls', 'go', 'jsse', 'libressl', 'mbedtls', 'nss', 'openssl', 's2n', 'schannel']
>>> catalog.versions("openssl")[:3]
['1.0.2', '1.1.0', '1.1.1']
```

Version labels are strings. Keep them in the order that `versions`
returns: it is the library's own version order, oldest first.

## Use the command line

The same data is available without writing Python. This command prints
the suites of Go 1.12 as a JSON list. The output is long, so only its
start is shown here:

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

[Command line](cli.md) documents every option.

## Next steps

- [Python API reference](api.md) documents every function and class.
- [Find a suite by name](name-resolution.md) explains ambiguous names.
- [Errors](errors.md) lists what can go wrong.
