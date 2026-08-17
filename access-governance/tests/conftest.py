import datetime as dt
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agp.policy import GovernancePolicy  # noqa: E402

# Every time-sensitive assertion is pinned to this instant so the suite does not
# start failing on a future Tuesday.
NOW = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def samples():
    return ROOT / "samples"


@pytest.fixture
def policy():
    return GovernancePolicy.load(ROOT / "config" / "governance-policy.yaml")
