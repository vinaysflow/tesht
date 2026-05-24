"""
tests/fixtures/conftest.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Session-scoped pytest fixture providing the deterministic synthetic dataset.
Import this conftest.py's fixture in any test by including `synthetic_data`
as a function argument — pytest auto-discovers it via conftest.py.
"""
import pytest
from tests.fixtures.synthetic_data import SyntheticDataGenerator, SyntheticDataSet


@pytest.fixture(scope="session")
def synthetic_data() -> SyntheticDataSet:
    """Generate and cache the full synthetic dataset once per test session."""
    gen = SyntheticDataGenerator(seed=42)
    return gen.generate_all()
