"""Reference sources: lists of suites that are not a TLS library.

IANA, testssl and Scanigma are compared against the libraries rather than
being libraries themselves. Importing this package registers all three.
"""

from __future__ import annotations

# pylint: disable-next=unused-import
from ciphersuites.scrape.adapters.reference import (  # noqa: F401
    iana,
    scanigma,
    testssl,
)
