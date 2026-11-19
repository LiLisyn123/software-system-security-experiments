import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def work_dir():
    """A writable directory inside the project (avoids pytest's temp dir ACLs)."""
    base = ROOT / "tests" / "_output"
    base.mkdir(parents=True, exist_ok=True)
    yield base
    for path in base.iterdir():
        if path.is_file():
            try:
                path.unlink()
            except OSError:
                pass
