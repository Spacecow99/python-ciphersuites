# TLS cipher suites and code points

This page explains the TLS terms that the rest of the documentation uses.
It starts from zero. If you already know what a cipher suite and a code
point are, read only the section
[Why libraries use different names](#why-libraries-use-different-names).

## TLS and SSL

{term}`TLS` (Transport Layer Security) protects the data that two programs
send to each other, for example a web browser and a web server. TLS
encrypts the data and checks that nobody changed it. TLS also lets one
side prove who it is.

{term}`SSL` (Secure Sockets Layer) is the older protocol that TLS
replaced. SSL 2.0 and SSL 3.0 are obsolete and not safe. Old library
versions still contain them, so the data in this project still records
them.

{term}`DTLS` (Datagram TLS) is a form of TLS for transports such as UDP.

## What a cipher suite is

TLS can use many different algorithms. Before the two programs send any
data, they run a {term}`handshake`. In the handshake they agree which
algorithms to use. A {term}`cipher suite` is a named set of algorithms
that the two sides use together.

The client sends a list of the cipher suites that it accepts. The server
chooses one suite from that list. Both sides then use the algorithms of
that suite.

Before TLS 1.3, a cipher suite names four algorithms. Take
`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` as an example:

| Part of the name | Role | Meaning |
|---|---|---|
| `ECDHE` | key exchange | how the two sides agree on a secret key |
| `RSA` | authentication | how the server proves who it is |
| `AES_128_GCM` | encryption | how the data is encrypted |
| `SHA256` | hash | the hash function that the suite uses |

A {term}`TLS 1.3 suite` names fewer algorithms. For example,
`TLS_AES_128_GCM_SHA256` names only the encryption and the hash. TLS 1.3
agrees on the key exchange and the authentication separately.

## What a code point is

A TLS handshake does not send the name of a cipher suite. It sends a
number. This number is the {term}`code point` of the suite. In TLS, a code
point is two bytes.

People write a code point as two hexadecimal bytes. For example, the code
point of `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` is `0xC0,0x2F`. The data
files in this project write it as a list of strings, always with
uppercase hex digits and a lowercase `x`:

```yaml
code_point:
- '0xC0'
- '0x2F'
```

The code point is the identity of a cipher suite. Two libraries that
support `0xC0,0x2F` support the same suite, whatever names they use.

## IANA, the registry of code points

{term}`IANA` (the Internet Assigned Numbers Authority) keeps the official
list of TLS cipher suites. The list is the "TLS Cipher Suites" registry.
For each code point, it gives:

- a name, for example `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`;
- whether the suite may be used with DTLS;
- whether the {term}`IETF` recommends the suite.

The names in the IANA registry start with `TLS_`. This documentation
calls them *IANA names*. The project reads the registry as one of its
{term}`reference source`s. See
[Reference sources](../data/reference-sources.md).

## SSLv2 three-byte code points

{term}`SSLv2` (SSL version 2.0) used code points of three bytes, not two.
For example, `0x01,0x00,0x80` is the SSLv2 suite with RC4 encryption and
an MD5 hash. testssl.sh and Scanigma call it `SSL_CK_RC4_128_WITH_MD5`.
OpenSSL 1.0.2 calls it `RC4-MD5`.

The IANA TLS registry does not list three-byte code points. The data in
this project keeps them, because old versions of OpenSSL, LibreSSL and
Schannel define them. In the data files, a three-byte code point is a
list of three strings:

```yaml
code_point:
- '0x01'
- '0x00'
- '0x80'
```

A three-byte code point is always a different code point from every
two-byte code point. Do not shorten it or pad it.

## Signalling values (SCSVs)

Some code points do not name a cipher suite at all. A client puts them in
its list of suites to send a signal to the server. They are called
{term}`SCSV`s (Signalling Cipher Suite Values). A server never chooses an
SCSV as the suite of a connection.

The data contains two SCSVs:

| Code point | Name | Signal |
|---|---|---|
| `0x00,0xFF` | `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` | the client supports secure renegotiation ({term}`RFC` 5746) |
| `0x56,0x00` | `TLS_FALLBACK_SCSV` | the client retried the handshake with a lower protocol version (RFC 7507) |

The data lists an SCSV for a library version when that version defines
it. For example, every tracked version of OpenSSL, BoringSSL and NSS
defines both. If you
want only real cipher suites, remove these two code points from your
results.

## Why libraries use different names

Each TLS library chose its own style of names for cipher suites. So one
code point has many names. Here is `0xC0,0x2F` in each
library, as the data records it:

| Library | Name |
|---|---|
| OpenSSL, LibreSSL, BoringSSL, s2n-tls | `ECDHE-RSA-AES128-GCM-SHA256` |
| GnuTLS | `TLS_ECDHE_RSA_AES_128_GCM_SHA256` |
| Mbed TLS | `TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256` |
| Go, JSSE, NSS, Schannel | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |

Names cause three more problems:

1. **A library can rename a suite.** BoringSSL called `0x13,0x01`
   `AEAD-AES128-GCM-SHA256` up to its 2018-05-02 version. From its
   2023-04-24 version, it calls the same code point
   `TLS_AES_128_GCM_SHA256`.
2. **A library can use two names for one code point at the same time.**
   OpenSSL defines both `DHE-RSA-DES-CBC3-SHA` and `EDH-RSA-DES-CBC3-SHA`
   for `0x00,0x16`. NSS defines both `SSL_RSA_WITH_RC4_128_SHA` and
   `TLS_RSA_WITH_RC4_128_SHA` for `0x00,0x05`.
3. **One name can mean two code points.** In OpenSSL 1.0.2, `RC4-MD5` is
   the name of the TLS suite `0x00,0x04` and also of the SSLv2 suite
   `0x01,0x00,0x80`.

For these reasons, this project uses the code point as the key for every
suite. A name is only a property of a code point in one library version.
To compare libraries, always compare code points, never names.

The example below reads the OpenSSL data file with PyYAML and shows the
third problem. It finds every code point that OpenSSL 1.0.2 calls
`RC4-MD5`:

```pycon
>>> import yaml
>>> with open("ciphersuites/_ciphersuites/openssl.yaml", encoding="utf-8") as f:
...     doc = yaml.safe_load(f)
>>> [
...     suite["code_point"]
...     for suite in doc["suites"]
...     for entry in suite["names"]
...     if entry["name"] == "RC4-MD5" and "1.0.2" in entry["versions"]
... ]
[['0x00', '0x04'], ['0x01', '0x00', '0x80']]
```

The [data guide](../data/reading-the-data.md) shows more examples like
this one.

## Next step

Read [How libraries, versions and suites relate](data-model.md). It
explains how the data files store suites, names and versions.
