"""Test fixtures for EuRedact."""

import pytest
from euredact.sdk import EuRedact


@pytest.fixture
def sdk():
    """Fresh EuRedact instance per test."""
    return EuRedact()
