"""Base country configuration class."""

from __future__ import annotations

from dataclasses import dataclass, field

from euredact.types import EntityType


@dataclass
class PatternDef:
    """A single pattern definition."""

    entity_type: EntityType | str
    pattern: str
    validator: str | None = None
    description: str = ""
    context_keywords: list[str] = field(default_factory=list)
    requires_context: bool = False


@dataclass
class CountryConfig:
    """Base class for country-specific PII patterns."""

    code: str = ""
    name: str = ""
    patterns: list[PatternDef] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Override in subclasses to populate patterns."""
