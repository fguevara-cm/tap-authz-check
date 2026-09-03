from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from tap_authz_check.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
