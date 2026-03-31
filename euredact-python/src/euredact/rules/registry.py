"""Country registry with auto-discovery.

Adding a new country requires only one step: create a file in the
``countries/`` package (e.g. ``es.py``) that defines a subclass of
``CountryConfig``.  The registry discovers it automatically by scanning
the package for modules whose ``CountryConfig`` subclass has a non-empty
``code`` attribute.  Files prefixed with ``_`` (like ``_base.py`` and
``_shared.py``) are treated specially — ``_shared.py`` is always loaded
and ``_base.py`` is skipped.
"""

from __future__ import annotations

import importlib
import pkgutil

import euredact.rules.countries as _countries_pkg
from euredact.rules.countries._base import CountryConfig


class CountryRegistry:
    """Manages country configs with lazy loading and auto-discovery."""

    def __init__(self) -> None:
        self._configs: dict[str, CountryConfig] = {}
        self._available: dict[str, type[CountryConfig]] = {}
        self._discover()

    def _discover(self) -> None:
        """Scan the countries package for CountryConfig subclasses."""
        pkg_path = _countries_pkg.__path__
        for finder, module_name, _ in pkgutil.iter_modules(pkg_path):
            if module_name == "_base":
                continue
            full_name = f"euredact.rules.countries.{module_name}"
            mod = importlib.import_module(full_name)
            for attr in vars(mod).values():
                if (
                    isinstance(attr, type)
                    and issubclass(attr, CountryConfig)
                    and attr is not CountryConfig
                ):
                    # Instantiate temporarily to read the code
                    instance = attr()
                    if instance.code:
                        self._available[instance.code] = attr

    def load(self, country_code: str) -> CountryConfig:
        """Load a country config on demand. Idempotent."""
        code = country_code.upper()
        if code not in self._configs:
            if code not in self._available:
                raise ValueError(
                    f"Unknown country code: {code!r}. "
                    f"Available: {sorted(self._available)}"
                )
            cls = self._available[code]
            self._configs[code] = cls()
        return self._configs[code]

    def load_all(self) -> list[CountryConfig]:
        """Load all registered countries."""
        return [self.load(code) for code in self._available]

    @property
    def available_countries(self) -> list[str]:
        """Return list of available country codes (excluding SHARED)."""
        return sorted(c for c in self._available if c != "SHARED")
