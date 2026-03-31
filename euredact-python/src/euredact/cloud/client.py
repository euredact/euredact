"""[CLOUD EXTENSION] Placeholder cloud client."""

from __future__ import annotations


class NotConfiguredError(Exception):
    """Raised when cloud tier is used without configuration."""

    def __init__(self) -> None:
        super().__init__(
            "Cloud tier not configured. Call euredact.configure(api_key=...) first."
        )


class CloudClient:
    """Placeholder for the cloud annotation client."""

    def __init__(self) -> None:
        raise NotConfiguredError()
