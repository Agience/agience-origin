"""Print a one-time code for enrolling the platform operator's first passkey.

Run on Origin's own host, against Origin's database; there is no HTTP route that issues one, and
Mantle cannot read it. The code lives fifteen minutes, is spent by the enrolment it authorizes, and
replaces any earlier unused code. The operator's browser sends it in `X-Operator-Enrolment-Code` to
`/auth/passkey/register-options` and `/auth/passkey/register-complete`. Once the operator has a
passkey, further passkeys on that account need the operator console with a step-up instead.

    python -m origin.scripts.operator_enrolment_code
"""
from __future__ import annotations

import sys


def main() -> int:
    from origin.db.session import SessionLocal
    from origin.services import operator_console
    from origin.services.platform_settings_service import settings as platform_settings

    with SessionLocal() as db:
        platform_settings.load_all(db)
        operator = platform_settings.get("platform.operator_id")
        if not operator:
            print("no platform operator is set", file=sys.stderr)
            return 1
        print(operator_console.issue_enrolment_code(db, str(operator)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
