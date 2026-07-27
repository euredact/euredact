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
import warnings

import euredact.rules.countries as _countries_pkg
from euredact.rules.countries._base import CountryConfig

# The country modules use the EU/VAT convention (UK, EL) while the public
# contract is ISO 3166-1 alpha-2 (GB, GR). Accept both spellings so a caller
# passing correct ISO codes is not punished for it.
COUNTRY_CODE_ALIASES: dict[str, str] = {
    "GB": "UK",   # ISO 3166-1 alpha-2 -> EU/VAT convention
    "GR": "EL",
    "UK": "UK",
    "EL": "EL",
}


class UnknownCountryWarning(UserWarning):
    """Raised as a warning when an unrecognised country code is requested."""


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

    def resolve(self, country_code: str) -> str | None:
        """Map a caller-supplied code to a registered one, or None if unknown.

        Accepts ISO 3166-1 alpha-2 (``GB``, ``GR``) as well as the EU/VAT
        spellings the country modules use (``UK``, ``EL``).
        """
        code = country_code.strip().upper()
        code = COUNTRY_CODE_ALIASES.get(code, code)
        return code if code in self._available else None

    def load(self, country_code: str) -> CountryConfig | None:
        """Load a country config on demand. Idempotent.

        An unrecognised code returns ``None`` with a warning rather than
        raising: a redaction library that throws on an unknown locale invites
        callers to wrap it in ``try/except`` and skip redaction entirely,
        which fails open and leaks PII. Detection continues with the shared
        (country-independent) patterns.
        """
        code = self.resolve(country_code)
        if code is None:
            warnings.warn(
                f"Unknown country code: {country_code!r}. Continuing with "
                f"shared country-independent patterns only (email, IBAN, "
                f"international phone, credit card, ...). "
                f"Available: {sorted(self.available_countries)}",
                UnknownCountryWarning,
                stacklevel=3,
            )
            return None
        if code not in self._configs:
            self._configs[code] = self._available[code]()
        return self._configs[code]

    def load_all(self) -> list[CountryConfig]:
        """Load all registered countries."""
        configs = [self.load(code) for code in self._available]
        return [c for c in configs if c is not None]

    @property
    def available_countries(self) -> list[str]:
        """Return list of available country codes (excluding SHARED)."""
        return sorted(c for c in self._available if c != "SHARED")
