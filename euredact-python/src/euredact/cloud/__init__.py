"""[CLOUD EXTENSION] Cloud tier — rules engine plus a fine-tuned model.

The rule engine catches what has a shape: IBANs, national IDs, phone numbers,
anything with a checksum. It cannot catch what does not — a person's name, an
employer, a diagnosis, a job title. Those are what the cloud tier adds, and the
type list in :class:`euredact.EntityType` marked ``[CLOUD EXTENSION]`` is
exactly that gap.

    import euredact
    euredact.configure(api_key="erk_...")
    result = euredact.redact(text, countries=["BE"], mode="cloud")

Requires the ``cloud`` extra::

    pip install 'euredact[cloud]'
"""

from euredact.cloud.account import (
    Account,
    AccountSummary,
    ApiKey,
    CreditEntry,
    Credits,
    Job,
    Jobs,
    KeyRevocation,
    KeyUsage,
    UsageDay,
)
from euredact.cloud.batches import (
    Batch,
    BatchError,
    Batches,
    BatchResults,
    DocumentOutcome,
    FileBatchStore,
)
from euredact.cloud.client import (
    AsyncCloudClient,
    CloudClient,
    CloudError,
    NotConfiguredError,
    NotFoundError,
    QuotaExceededError,
    RateLimitedError,
    ResultExpiredError,
    TooLargeError,
)
from euredact.cloud.config import CloudConfig, configure, get_config, reset

__all__ = [
    "Account",
    "AccountSummary",
    "ApiKey",
    "AsyncCloudClient",
    "Batch",
    "BatchError",
    "BatchResults",
    "Batches",
    "CloudClient",
    "CloudConfig",
    "CloudError",
    "CreditEntry",
    "Credits",
    "DocumentOutcome",
    "FileBatchStore",
    "Job",
    "Jobs",
    "KeyRevocation",
    "KeyUsage",
    "NotConfiguredError",
    "NotFoundError",
    "QuotaExceededError",
    "RateLimitedError",
    "ResultExpiredError",
    "TooLargeError",
    "UsageDay",
    "configure",
    "get_config",
    "reset",
]
