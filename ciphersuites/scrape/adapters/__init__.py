"""Source adapters for the cipher suite scraping pipeline.

Adapters register themselves with ``@register`` when their module is
imported, so every adapter module under this package (including future
subpackages such as ``reference``) MUST be imported here, after ``base``,
or ``get_adapter`` and the fixture capture CLI report "unknown adapter".
``tests/test_adapter_base.py`` enforces this.
"""

from __future__ import annotations

# base must come first: adapter modules import it, and registration needs it.
from ciphersuites.scrape.adapters.base import (
    ADAPTERS,
    Adapter,
    get_adapter,
    register,
)

# pylint: disable-next=wrong-import-position,unused-import
from ciphersuites.scrape.adapters import (  # noqa: E402,F401
    boringssl,
    go,
    libressl,
    nss,
    openssl,
)

__all__ = ["ADAPTERS", "Adapter", "get_adapter", "register"]
