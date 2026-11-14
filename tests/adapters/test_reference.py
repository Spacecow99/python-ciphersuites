"""Tests for the IANA, testssl and Scanigma reference adapters."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import responses

from ciphersuites.scrape.adapters import ADAPTERS, get_adapter
from ciphersuites.scrape.adapters.reference import testssl
from ciphersuites.scrape.adapters.reference.iana import Iana
from ciphersuites.scrape.adapters.reference.scanigma import Scanigma
from ciphersuites.scrape.adapters.reference.testssl import TestSsl
from ciphersuites.scrape.core import Record, Version
from ciphersuites.scrape.fetch import Fetcher
from tests.golden import assert_matches_golden

LABEL = "2026-11-08"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
SHA = "a" * 40
IANA_URL = (
    "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
)
LISTING = "https://scanigma.com/knowledge-base/tls/ciphersuite/"
HEADER = "Value,Description,DTLS-OK,Recommended,Reference,Comment\n"
SCANIGMA_DETAIL_FILES = 8


def _iana(*rows):
    return Iana().parse({"tls-parameters-4.csv": HEADER + "".join(rows)})


def _testssl(text):
    return TestSsl().parse({"etc/cipher-mapping.txt": text})


def _tline(value, name, openssl="X-Y", version="TLSv1.2"):
    return (
        f"      {value} - {openssl:<20} {name:<40} {version:<8} Kx=RSA"
        "        Au=RSA     Enc=AES(128)         Mac=SHA1\n"
    )


# ---------------------------------------------------------------- registry


def test_registered_as_reference_adapters():
    for name, cls in (("iana", Iana), ("testssl", TestSsl)):
        assert ADAPTERS[name] is cls
        assert isinstance(get_adapter(name), cls)
        assert cls.kind == "reference"
    assert ADAPTERS["scanigma"] is Scanigma
    assert Scanigma.kind == "reference"


@pytest.mark.parametrize("cls", [Iana, TestSsl, Scanigma])
def test_reference_adapters_keep_one_rolling_version(cls):
    assert cls.rolling is True
    assert cls.keep_last == 1


# -------------------------------------------------------------------- IANA


def test_iana_fixture(upstream):
    result = Iana().parse(upstream("iana", LABEL))
    cp = ("0xC0", "0x2F")
    assert Record("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cp) in result.records
    assert result.attributes[cp] == {"dtls_ok": True, "recommended": "Y"}
    for record in result.records:
        assert not record.name.startswith(("Reserved", "Unassigned"))
    assert result.join_coverage >= 0.90
    assert not result.unmatched_keys


def test_iana_fixture_attribute_values(upstream):
    result = Iana().parse(upstream("iana", LABEL))
    assert set(result.attributes) == {r.code_point for r in result.records}
    for attrs in result.attributes.values():
        assert isinstance(attrs["dtls_ok"], bool)
        assert attrs["recommended"] in ("Y", "N", "D")


def test_iana_fixture_golden(upstream, update_goldens):
    result = Iana().parse(upstream("iana", LABEL))
    assert_matches_golden(update_goldens, "iana", LABEL, result)


def test_iana_discover_and_fetch():
    adapter = Iana(now=NOW)
    (version,) = adapter.discover_versions()
    assert version == Version(LABEL, IANA_URL, None)
    assert adapter.files_for(version) == ["tls-parameters-4.csv"]
    assert adapter.source_url(version, "tls-parameters-4.csv") == IANA_URL
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, IANA_URL, body=b"data")
        files = adapter.fetch_files(version, Fetcher(None))
    assert files == {"tls-parameters-4.csv": b"data"}


def test_iana_fetch_is_not_cached(tmp_path):
    adapter = Iana(now=NOW)
    (version,) = adapter.discover_versions()
    fetcher = Fetcher(tmp_path)
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, IANA_URL, body=b"one")
        rsps.add(responses.GET, IANA_URL, body=b"two")
        first = adapter.fetch_files(version, fetcher)
        second = adapter.fetch_files(version, fetcher)
    assert first != second
    assert not list(tmp_path.iterdir())


def test_iana_excludes_reserved_and_unassigned():
    result = _iana(
        '"0x00,0x01",TLS_RSA_WITH_NULL_MD5,Y,D,[RFC 5246],\n',
        '"0x0A,0x0A",Reserved,Y,N,[RFC 8701],\n',
        '"0x00,0x5D-5F",Unassigned,,,,\n',
        '"0x00,0x1C-1D",Reserved to avoid conflicts with SSLv3,,,,\n',
    )
    assert result.records == [Record("TLS_RSA_WITH_NULL_MD5", ("0x00", "0x01"))]
    assert result.total_keys == 1
    assert not result.unmatched_keys


def test_iana_multiline_quoted_description_is_one_row():
    result = _iana(
        '"0x00,0x47-4F","Reserved to avoid conflicts with\n  deployed",,,,\n',
        '"0x00,0x01",TLS_RSA_WITH_NULL_MD5,Y,D,,\n',
    )
    assert len(result.records) == 1


def test_iana_expands_ranges_of_named_rows():
    result = _iana(
        '"0x00,0x10-12",TLS_X,N,D,,\n',
        '"0x01-02,*",TLS_Y,Y,N,,\n',
    )
    x = [r.code_point for r in result.records if r.name == "TLS_X"]
    assert x == [("0x00", "0x10"), ("0x00", "0x11"), ("0x00", "0x12")]
    y = [r for r in result.records if r.name == "TLS_Y"]
    assert len(y) == 512
    assert result.attributes[("0x00", "0x11")] == {
        "dtls_ok": False,
        "recommended": "D",
    }


@pytest.mark.parametrize(
    "row",
    [
        '"0xC0",TLS_X,Y,Y,,\n',
        '"0xC0,0xZZ",TLS_X,Y,Y,,\n',
        '"0xC0,0x2F",TLS_X,maybe,Y,,\n',
        '"0xC0,0x2F",TLS_X,Y,Q,,\n',
        '"0xC0,0x2F",,Y,Y,,\n',
    ],
)
def test_iana_unparseable_row_is_unmatched(row):
    result = _iana(row, '"0x00,0x01",TLS_A,Y,D,,\n')
    assert [r.name for r in result.records] == ["TLS_A"]
    assert result.total_keys == 2
    assert len(result.unmatched_keys) == 1
    assert result.join_coverage == 0.5


def test_iana_conflicting_names_for_one_code_point():
    with pytest.raises(ValueError, match="0xC0"):
        _iana(
            '"0xC0,0x2F",TLS_A,Y,Y,,\n',
            '"0xC0,0x2F",TLS_B,Y,Y,,\n',
        )


def test_iana_identical_duplicate_row_is_one_record():
    result = _iana('"0xC0,0x2F",TLS_A,Y,Y,,\n', '"0xC0,0x2F",TLS_A,Y,Y,,\n')
    assert len(result.records) == 1


def test_iana_missing_column_is_an_error():
    with pytest.raises(ValueError, match="Recommended"):
        Iana().parse({"tls-parameters-4.csv": "Value,Description,DTLS-OK\n"})


# ----------------------------------------------------------------- testssl


def test_testssl_fixture(upstream):
    result = TestSsl().parse(upstream("testssl", LABEL))
    by_cp = {r.code_point: r.name for r in result.records}
    assert ("0xCC", "0xA8") in by_cp
    assert ("0xCC", "0x13") in by_cp
    assert by_cp[("0xCC", "0xA8")] != by_cp[("0xCC", "0x13")]
    assert by_cp[("0xCC", "0xA8")] == (
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    )
    assert any(len(cp) == 3 for cp in by_cp)
    assert result.join_coverage >= 0.90
    assert not result.unmatched_keys


def test_testssl_fixture_golden(upstream, update_goldens):
    result = TestSsl().parse(upstream("testssl", LABEL))
    assert_matches_golden(update_goldens, "testssl", LABEL, result)


def test_testssl_discover_files_and_source(monkeypatch):
    monkeypatch.setattr(testssl, "ls_remote_head", lambda repo: SHA)
    adapter = TestSsl(now=NOW)
    (version,) = adapter.discover_versions()
    assert version == Version(
        LABEL, "HEAD", SHA, "https://github.com/testssl/testssl.sh"
    )
    assert adapter.files_for(version) == ["etc/cipher-mapping.txt"]
    assert adapter.source_url(version, "etc/cipher-mapping.txt") == (
        f"https://raw.githubusercontent.com/testssl/testssl.sh/{SHA}"
        "/etc/cipher-mapping.txt"
    )
    assert adapter.rolling


def test_testssl_skips_nameless_entries_without_penalty():
    result = _testssl(
        _tline("0xC0,0x3F", "-", openssl="-")
        + _tline("0x00,0x2F", "TLS_RSA_WITH_AES_128_CBC_SHA")
    )
    assert result.records == [
        Record("TLS_RSA_WITH_AES_128_CBC_SHA", ("0x00", "0x2F"))
    ]
    assert not result.unmatched_keys


def test_testssl_normalises_and_reads_three_byte_codes():
    result = _testssl(
        _tline("0xcc,0xa8", "TLS_A") + _tline("0x01,0x00,0x80", "SSL_CK_B")
    )
    assert [r.code_point for r in result.records] == [
        ("0xCC", "0xA8"),
        ("0x01", "0x00", "0x80"),
    ]


def test_testssl_format_change_lowers_coverage():
    result = _testssl(
        _tline("0x00,0x2F", "TLS_A") + "      0x00,0x35 - broken line\n"
    )
    assert result.total_keys == 2
    assert len(result.unmatched_keys) == 1
    assert "0x00,0x35" in result.unmatched_keys[0]
    assert result.join_coverage == 0.5


def test_testssl_ignores_non_entry_lines():
    result = _testssl("# comment\n\n" + _tline("0x00,0x2F", "TLS_A"))
    assert result.total_keys == 1


def test_testssl_blank_lines_between_entries_lose_nothing():
    result = _testssl(
        "\n\n"
        + _tline("0x00,0x2F", "TLS_A")
        + "\n   \n\t\n"
        + _tline("0x00,0x35", "TLS_B")
        + "\n"
        + _tline("0xC0,0x2F", "TLS_C")
    )
    assert sorted(r.name for r in result.records) == [
        "TLS_A",
        "TLS_B",
        "TLS_C",
    ]
    assert result.total_keys == 3
    assert not result.unmatched_keys


def test_testssl_fixture_with_blank_lines_keeps_every_record(upstream):
    files = upstream("testssl", LABEL)
    plain = TestSsl().parse(files)
    text = files["etc/cipher-mapping.txt"]
    spaced = TestSsl().parse(
        {"etc/cipher-mapping.txt": text.replace("\n", "\n\n")}
    )
    assert sorted(spaced.records, key=lambda r: r.name) == sorted(
        plain.records, key=lambda r: r.name
    )
    assert "" not in spaced.unmatched_keys
    assert spaced.unmatched_keys == plain.unmatched_keys


def test_testssl_conflicting_names_for_one_code_point():
    with pytest.raises(ValueError, match="0x00"):
        _testssl(_tline("0x00,0x2F", "TLS_A") + _tline("0x00,0x2F", "TLS_B"))


# ---------------------------------------------------------------- Scanigma


def _listing(*entries, count=None):
    items = [
        {"@type": "ListItem", "position": i, "name": n, "url": u}
        for i, (n, u) in enumerate(entries, 1)
    ]
    graph = {
        "@graph": [
            {"@type": "BreadcrumbList"},
            {
                "@type": "CollectionPage",
                "mainEntity": {
                    "@type": "ItemList",
                    "numberOfItems": len(items) if count is None else count,
                    "itemListElement": items,
                },
            },
        ]
    }
    return _html(graph)


def _detail(name, code):
    about = {"@type": "DefinedTerm", "name": name}
    if code is not None:
        about["termCode"] = code
    return _html({"@graph": [{"@type": "TechArticle", "about": about}]})


def _html(document):
    return (
        '<html><head><script type="application/ld+json">'
        + json.dumps(document)
        + "</script></head><body></body></html>"
    )


def _url(slug):
    return LISTING + slug


def _scan(listing, **details):
    files = {"listing.html": listing}
    files.update(
        {f"detail/{slug}.html": text for slug, text in details.items()}
    )
    return Scanigma().parse(files)


def test_scanigma_fixture(upstream):
    files = upstream("scanigma", LABEL)
    result = Scanigma().parse(files)
    details = [p for p in files if p.startswith("detail/")]
    assert len(details) == SCANIGMA_DETAIL_FILES
    assert len(result.records) == SCANIGMA_DETAIL_FILES
    assert result.total_keys > len(result.records) > 0
    assert len(result.unmatched_keys) == result.total_keys - len(result.records)
    names = {r.name: r.code_point for r in result.records}
    assert names["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"] == ("0xC0", "0x2F")
    assert names["OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"] == (
        "0xCC",
        "0x15",
    )
    assert names["TLS_AES_128_GCM_SHA256"] == ("0x13", "0x01")
    assert names["SSL_CK_RC4_128_WITH_MD5"] == ("0x01", "0x00", "0x80")


def test_scanigma_fixture_golden(upstream, update_goldens):
    result = Scanigma().parse(upstream("scanigma", LABEL))
    assert_matches_golden(update_goldens, "scanigma", LABEL, result)


def test_scanigma_discover_files_and_source_urls():
    adapter = Scanigma(now=NOW)
    (version,) = adapter.discover_versions()
    assert version == Version(LABEL, LISTING, None)
    assert adapter.files_for(version) == ["listing.html"]
    assert adapter.source_url(version, "listing.html") == LISTING
    assert adapter.source_url(version, "detail/tls-x.html") == _url("tls-x")


def test_scanigma_fetch_files_visits_listing_then_every_detail():
    adapter = Scanigma(now=NOW)
    (version,) = adapter.discover_versions()
    listing = _listing(("TLS_A", _url("tls-a")), ("TLS_B", _url("tls-b")))
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, LISTING, body=listing)
        rsps.add(responses.GET, _url("tls-a"), body="A")
        rsps.add(responses.GET, _url("tls-b"), body="B")
        files = adapter.fetch_files(version, Fetcher(None))
    assert files == {
        "listing.html": listing.encode(),
        "detail/tls-a.html": b"A",
        "detail/tls-b.html": b"B",
    }


def test_scanigma_records_and_term_code_normalisation():
    result = _scan(
        _listing(("TLS_A", _url("tls-a")), ("OLD_TLS_B", _url("old-b"))),
        **{
            "tls-a": _detail("TLS_A", "0xc0, 0x2f"),
            "old-b": _detail("OLD_TLS_B", "0xCC,0x15"),
        },
    )
    assert result.records == [
        Record("TLS_A", ("0xC0", "0x2F")),
        Record("OLD_TLS_B", ("0xCC", "0x15")),
    ]
    assert result.total_keys == 2
    assert not result.unmatched_keys


def test_scanigma_missing_detail_or_term_code_is_unmatched():
    result = _scan(
        _listing(
            ("TLS_A", _url("a")),
            ("TLS_B", _url("b")),
            ("TLS_C", _url("c")),
        ),
        a=_detail("TLS_A", "0x00, 0x01"),
        b=_detail("TLS_B", None),
    )
    assert [r.name for r in result.records] == ["TLS_A"]
    assert result.total_keys == 3
    assert result.unmatched_keys == ["TLS_B", "TLS_C"]


def test_scanigma_bad_term_code_is_unmatched():
    result = _scan(
        _listing(("TLS_A", _url("a"))), a=_detail("TLS_A", "0x00, 0xZZ")
    )
    assert not result.records
    assert result.unmatched_keys == ["TLS_A"]


def test_scanigma_uses_detail_name_not_listing_name():
    result = _scan(
        _listing(("TLS_LIST", _url("a"))), a=_detail("TLS_DETAIL", "0x00, 0x01")
    )
    assert result.records == [Record("TLS_DETAIL", ("0x00", "0x01"))]


def test_scanigma_never_borrows_code_points_by_name():
    result = _scan(
        _listing(("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", _url("a"))),
        a=_detail("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", None),
    )
    assert not result.records


def test_scanigma_conflicting_code_point_names():
    with pytest.raises(ValueError, match="0x00"):
        _scan(
            _listing(("TLS_A", _url("a")), ("TLS_B", _url("b"))),
            a=_detail("TLS_A", "0x00, 0x01"),
            b=_detail("TLS_B", "0x00, 0x01"),
        )


def test_scanigma_listing_without_item_list_is_an_error():
    with pytest.raises(ValueError, match="ItemList"):
        _scan(_html({"@graph": [{"@type": "WebPage"}]}))


def test_scanigma_listing_without_json_ld_is_an_error():
    with pytest.raises(ValueError, match="ItemList"):
        _scan("<html><body>no data</body></html>")


def test_scanigma_count_mismatch_lowers_coverage():
    """The page claims more entries than it lists: they count as unmatched."""
    result = _scan(
        _listing(("TLS_A", _url("a")), count=3),
        a=_detail("TLS_A", "0x00, 0x01"),
    )
    assert result.total_keys == 3
    assert len(result.unmatched_keys) == 2


def test_scanigma_malformed_json_ld_is_an_error():
    html = '<script type="application/ld+json">{oops</script>'
    with pytest.raises(ValueError):
        _scan(html)


def test_scanigma_item_without_url_is_unmatched_and_not_fetched():
    adapter = Scanigma(now=NOW)
    (version,) = adapter.discover_versions()
    listing = _listing(("TLS_A", ""), ("TLS_B", _url("b")))
    listing = listing.replace('"url": ""', '"url": null', 1)
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, LISTING, body=listing)
        rsps.add(responses.GET, _url("b"), body="B")
        files = adapter.fetch_files(version, Fetcher(None))
    assert sorted(files) == ["detail/b.html", "listing.html"]
    result = _scan(listing, b=_detail("TLS_B", "0x00, 0x01"))
    assert [r.name for r in result.records] == ["TLS_B"]
    assert result.total_keys == 2
    assert result.unmatched_keys == ["TLS_A"]
