"""Shared pytest fixtures for Hexbreaker tests."""

import pytest


@pytest.fixture
def fixed_seed() -> int:
    """A deterministic seed for reproducible case-generation tests."""
    return 4729
