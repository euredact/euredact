# Contributing to EuRedact

## Development Setup

```bash
git clone https://github.com/jnjs/euredact.git
cd euredact
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,fast]"
```

## Running Tests

```bash
# All unit tests
pytest tests/ --ignore=tests/eval_full.py --ignore=tests/test_structdata.py

# Specific country
pytest tests/countries/test_nl.py

# With verbose output
pytest -v --tb=short
```

## Linting and Type Checking

```bash
ruff check src/
mypy src/euredact/ --ignore-missing-imports
```

## Adding a New Country

Adding a country is a single-file operation. No registration or configuration changes needed.

### 1. Create the country file

Create `src/euredact/rules/countries/xx.py` (where `xx` is the ISO 3166-1 alpha-2 code):

```python
"""CountryName (XX) PII patterns."""
from __future__ import annotations
from euredact.rules.countries._base import CountryConfig, PatternDef
from euredact.types import EntityType

class XXConfig(CountryConfig):
    def __post_init__(self) -> None:
        self.code = "XX"
        self.name = "CountryName"
        self.patterns = [
            PatternDef(
                entity_type=EntityType.NATIONAL_ID,
                pattern=r"\b\d{9}\b",
                validator="xx_national_id",  # or None if no checksum
                description="XX National ID -- 9 digits",
            ),
            PatternDef(
                entity_type=EntityType.IBAN,
                pattern=r"\bXX\d{20}\b",
                validator="iban",
                description="XX IBAN -- XX + 20 digits",
            ),
            # ... more patterns
        ]
```

### 2. Add a validator (if checksum exists)

Add your validator function to `src/euredact/rules/validators.py`:

```python
def validate_xx_national_id(candidate: str) -> bool:
    """XX national ID: 9 digits with mod-11 check."""
    clean = re.sub(r"[\s\-]", "", candidate)
    if len(clean) != 9 or not clean.isdigit():
        return False
    # ... checksum logic ...
    return check == int(clean[-1])
```

Then add it to the `VALIDATORS` dict at the bottom of the file:

```python
VALIDATORS: dict[str, Callable[[str], bool]] = {
    # ... existing validators ...
    "xx_national_id": validate_xx_national_id,
}
```

### 3. That's it

The `CountryRegistry` auto-discovers your file on startup. Verify:

```python
import euredact
assert "XX" in euredact.available_countries()
```

### Pattern guidelines

- Use `\b` word boundaries to avoid matching substrings
- Set `validator=` for any pattern with a checksum algorithm
- Set `requires_context=True` for ambiguous patterns (postal codes, short numbers)
- Add `context_keywords=` with terms in all local languages
- Include both compact and spaced format variants
- Add `"Address:"` and `"Postal:"` to postal code keywords

## Suppression Filters

If a pattern type produces false positives, check `src/euredact/rules/suppressors.py`.
Suppressors are dispatched by entity type -- add yours to `_TYPE_SUPPRESSORS`.

## Benchmarks

```bash
python benchmarks/bench_engine.py
```
