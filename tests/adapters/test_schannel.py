"""Tests for the hand-curated Schannel adapter."""

from __future__ import annotations

from importlib import resources

import pytest
import yaml

from ciphersuites.scrape.adapters import ADAPTERS, get_adapter
from ciphersuites.scrape.adapters.schannel import Schannel, load_curated
from ciphersuites.scrape.core import Record, Version, normalize_code_point

FILE = "schannel_curated.yaml"


def _curated_text():
    return (
        resources.files("ciphersuites.scrape.data")
        .joinpath(FILE)
        .read_text(encoding="utf-8")
    )


def _entries():
    return yaml.safe_load(_curated_text())["versions"]


def _doc(*versions):
    return yaml.safe_dump({"versions": list(versions)})


def _entry(label, *suites):
    return {
        "label": label,
        "source": f"https://learn.microsoft.com/{label}",
        "suites": [{"name": n, "code_point": cp} for n, cp in suites],
    }


def _parse_version(version):
    adapter = Schannel()
    files = adapter.fetch_files(version, fetcher=None)
    return adapter.parse({k: v.decode("utf-8") for k, v in files.items()})


def test_registered():
    assert ADAPTERS["schannel"] is Schannel
    assert isinstance(get_adapter("schannel"), Schannel)
    assert Schannel.repo is None


def test_every_code_point_normalises():
    for entry in _entries():
        for suite in entry["suites"]:
            cp = suite["code_point"]
            assert normalize_code_point(cp) == tuple(cp), suite["name"]


def test_newest_windows_has_tls13():
    newest = Schannel().discover_versions()[-1]
    records = _parse_version(newest).records
    assert Record("TLS_AES_128_GCM_SHA256", ("0x13", "0x01")) in records


def test_discover_versions_one_per_entry_in_file_order():
    entries = _entries()
    versions = Schannel().discover_versions()
    assert versions == [Version(e["label"], e["source"], None) for e in entries]
    assert len(versions) == 18
    assert versions[0].label == "Windows Vista"
    assert versions[-1].label == "Windows Server 2025"
    assert all(
        v.ref.startswith("https://learn.microsoft.com/") for v in versions
    )


def test_version_order_is_file_order_not_line_key():
    adapter = Schannel()
    labels = [v.label for v in adapter.discover_versions()]
    assert adapter.version_order(list(reversed(labels))) == labels
    assert adapter.version_order(["Windows 8.1", "Windows 7"]) == [
        "Windows 7",
        "Windows 8.1",
    ]


EXPECTED_COUNTS = {
    "Windows Vista": 24,
    "Windows 7": 41,
    "Windows 8": 39,
    "Windows 8.1": 41,
    "Windows 10 1507": 43,
    "Windows 10 1511": 43,
    "Windows 10 1607": 45,
    "Windows 10 1703": 45,
    "Windows 10 1709": 45,
    "Windows 10 1803": 45,
    "Windows 10 1809": 45,
    "Windows 10 1903": 45,
    "Windows 10 20H2": 45,
    "Windows Server 2022": 48,
    "Windows 11": 48,
    "Windows 11 22H2": 48,
    "Windows 10 22H2": 45,
    "Windows Server 2025": 48,
}


def test_suite_count_per_version():
    """Counts from the Microsoft Learn pages (all tables and lists)."""
    counts = {
        v.label: len(_parse_version(v).records)
        for v in Schannel().discover_versions()
    }
    assert counts == EXPECTED_COUNTS
    assert list(counts) == list(EXPECTED_COUNTS)


def test_vista_includes_suites_from_not_present_by_default_list():
    records = _parse_version(Schannel().discover_versions()[0]).records
    assert Record("TLS_RSA_WITH_DES_CBC_SHA", ("0x00", "0x09")) in records
    assert (
        Record("SSL_CK_DES_64_CBC_WITH_MD5", ("0x06", "0x00", "0x40"))
        in records
    )
    assert (
        Record("SSL_CK_RC4_128_EXPORT40_WITH_MD5", ("0x02", "0x00", "0x80"))
        in records
    )


def test_version_order_unknown_label_is_value_error():
    with pytest.raises(ValueError, match="Windows 95"):
        Schannel().version_order(["Windows 7", "Windows 95"])


def test_files_and_source_url():
    adapter = Schannel()
    version = adapter.discover_versions()[3]
    assert adapter.files_for(version) == [FILE]
    assert adapter.source_url(version, FILE) == version.ref


def test_parse_each_version_gives_exactly_its_suites():
    adapter = Schannel()
    for version, entry in zip(adapter.discover_versions(), _entries()):
        result = _parse_version(version)
        expected = [
            Record(s["name"], tuple(s["code_point"])) for s in entry["suites"]
        ]
        assert result.records == expected, version.label
        assert result.total_keys == len(entry["suites"])
        assert not result.unmatched_keys


def test_fetch_files_returns_only_that_versions_slice():
    adapter = Schannel()
    first, last = (
        adapter.discover_versions()[0],
        adapter.discover_versions()[-1],
    )
    one = adapter.fetch_files(first, fetcher=None)
    two = adapter.fetch_files(last, fetcher=None)
    assert list(one) == [FILE] == list(two)
    assert one[FILE] != two[FILE]
    assert len(yaml.safe_load(one[FILE])["versions"]) == 1


def test_names_unique_within_each_version():
    for entry in _entries():
        names = [s["name"] for s in entry["suites"]]
        assert len(names) == len(set(names)), entry["label"]


def test_curated_data_passes_validation():
    assert [e["label"] for e in load_curated(_curated_text())] == [
        e["label"] for e in _entries()
    ]


def test_duplicate_name_within_version_is_an_error():
    text = _doc(_entry("A", ("X", ["0x00", "0x01"]), ("X", ["0x00", "0x01"])))
    with pytest.raises(ValueError, match="duplicate"):
        load_curated(text)


def test_name_with_two_code_points_across_versions_is_an_error():
    text = _doc(
        _entry("A", ("X", ["0x00", "0x01"])),
        _entry("B", ("X", ["0x00", "0x02"])),
    )
    with pytest.raises(ValueError, match="two code points"):
        load_curated(text)


def test_bad_code_point_is_an_error():
    with pytest.raises(ValueError):
        load_curated(_doc(_entry("A", ("X", ["0x00", "0xZZ"]))))


def test_duplicate_label_is_an_error():
    text = _doc(_entry("A"), _entry("A"))
    with pytest.raises(ValueError, match="label"):
        load_curated(text)


def test_missing_keys_are_an_error():
    with pytest.raises(ValueError, match="versions"):
        load_curated("other: []\n")
