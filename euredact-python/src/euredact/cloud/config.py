"""[CLOUD EXTENSION] Cloud tier configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_BASE_URL = "https://api.euredact.dev"

#: How long to wait for a single document before giving up. The service holds a
#: connection open for its sync window and then hands back a job handle, so this
#: has to exceed that window or the client abandons requests the service is
#: about to answer.
DEFAULT_TIMEOUT_S = 90.0

#: Total wall-clock budget for a document that outlives the sync window and has
#: to be polled. Cold-starting a GPU node and loading an ~18 GB checkpoint takes
#: minutes, and an async job absorbs that invisibly -- but not forever.
DEFAULT_POLL_TIMEOUT_S = 900.0

DEFAULT_MAX_RETRIES = 3


@dataclass(frozen=True)
class CloudConfig:
    #: Kept out of ``repr()``. A frozen dataclass prints every field by default,
    #: so the key would otherwise reach anywhere the config is rendered -- a
    #: traceback frame, a debugger, a log line that formats the object -- and a
    #: credential that leaks does so long after the line that printed it was
    #: written. It is still an ordinary required argument.
    api_key: str = field(repr=False)
    base_url: str = DEFAULT_BASE_URL
    timeout_s: float = DEFAULT_TIMEOUT_S
    poll_timeout_s: float = DEFAULT_POLL_TIMEOUT_S
    max_retries: int = DEFAULT_MAX_RETRIES
    #: Extra headers, for a proxy or a self-hosted deployment.
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ValueError("api_key must not be empty")
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))


_config: CloudConfig | None = None


def configure(
    api_key: str | None = None,
    *,
    base_url: str | None = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    poll_timeout_s: float = DEFAULT_POLL_TIMEOUT_S,
    max_retries: int = DEFAULT_MAX_RETRIES,
    headers: dict[str, str] | None = None,
) -> CloudConfig:
    """Configure the cloud tier.

    Falls back to ``EUREDACT_API_KEY`` and ``EUREDACT_BASE_URL`` so a key never
    has to be written into source to get started.
    """
    key = api_key or os.getenv("EUREDACT_API_KEY", "")
    if not key:
        raise ValueError(
            "no API key: pass configure(api_key=...) or set EUREDACT_API_KEY")
    global _config
    _config = CloudConfig(
        api_key=key,
        base_url=base_url or os.getenv("EUREDACT_BASE_URL", DEFAULT_BASE_URL),
        timeout_s=timeout_s,
        poll_timeout_s=poll_timeout_s,
        max_retries=max_retries,
        headers=dict(headers or {}),
    )
    return _config


def get_config() -> CloudConfig | None:
    """The active configuration, or None. Never raises."""
    return _config


def reset() -> None:
    """Forget the configuration. Mainly for tests."""
    global _config
    _config = None
