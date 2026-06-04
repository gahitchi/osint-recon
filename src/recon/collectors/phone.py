"""Phone collector: fully deterministic, offline parsing via libphonenumber.

No account-existence probing against messengers by default — those endpoints
are unreliable and frequently ToS-restricted (a false-positive and ethics risk).
We surface validated metadata (region, carrier, line type, timezones) instead.
"""

from __future__ import annotations

from typing import Awaitable, Callable

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from ..http_client import RateLimitedClient
from ..models import Finding, Query, Verdict

EmitFn = Callable[[Finding], Awaitable[None]]


async def collect(query: Query, client: RateLimitedClient, emit: EmitFn) -> None:
    raw = query.phone
    if not raw:
        return
    try:
        num = phonenumbers.parse(raw, None)
    except phonenumbers.NumberParseException as e:
        await emit(Finding(
            source="phone:parse", category="phone", label="Phone parse",
            verdict=Verdict.ERROR, reasons=[f"could not parse (include country code, e.g. +1...): {e}"],
        ))
        return

    valid = phonenumbers.is_valid_number(num)
    if not valid:
        await emit(Finding(
            source="phone:validate", category="phone", label="Phone number",
            verdict=Verdict.NOT_FOUND, confidence=0.0,
            reasons=["number is not valid for any region"],
        ))
        return

    line_type = phonenumbers.number_type(num)
    type_name = {
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
        phonenumbers.PhoneNumberType.VOIP: "voip",
        phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
    }.get(line_type, "unknown")

    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    await emit(Finding(
        source="phone:validate", category="phone", label="Phone metadata",
        verdict=Verdict.FOUND, confidence=0.85,
        reasons=["valid number parsed offline (libphonenumber)"],
        signals={"phone_e164": e164},
        data={
            "e164": e164,
            "region": geocoder.description_for_number(num, "en"),
            "country_code": num.country_code,
            "carrier": carrier.name_for_number(num, "en") or None,
            "line_type": type_name,
            "timezones": list(timezone.time_zones_for_number(num)),
        },
    ))
