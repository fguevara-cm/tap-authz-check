"""Allow ``python -m tap_authz_check``."""

from tap_authz_check.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
