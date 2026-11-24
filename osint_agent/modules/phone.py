"""Offline phone intelligence via the phonenumbers metadata bundle. Makes no network calls."""

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from osint_agent.core.models import DEFAULT_REGION, Finding, ModuleResult, Seed

NAME = "phone"
SUPPORTS = {"phone"}

# int -> "mobile", "fixed_line", ... built from the library so new types need no change here.
_LINE_TYPES = {
    v: k.lower()
    for k, v in vars(phonenumbers.PhoneNumberType).items()
    if isinstance(v, int) and not k.startswith("_")
}


def _finding(entity_type: str, value: str, confidence: float, **raw) -> Finding:
    return Finding(
        module=NAME,
        entity_type=entity_type,
        value=value,
        source_url=None,
        confidence=confidence,
        raw=raw,
    )


async def run(seed: Seed, client) -> ModuleResult:
    result = ModuleResult(module=NAME)

    try:
        number = phonenumbers.parse(seed.value.strip(), DEFAULT_REGION)
    except phonenumbers.NumberParseException as exc:
        result.errors.append(f"could not parse {seed.value!r} as a phone number: {exc}")
        return result

    if not phonenumbers.is_valid_number(number):
        possible = phonenumbers.is_possible_number(number)
        result.errors.append(
            f"{seed.value!r} is not a valid number for region {DEFAULT_REGION} "
            f"(possible={possible})"
        )
        return result

    result.findings.append(
        _finding("validity", "valid", 1.0, possible=phonenumbers.is_possible_number(number))
    )
    result.findings.append(
        _finding(
            "e164",
            phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
            1.0,
            country_code=number.country_code,
            national_number=number.national_number,
        )
    )
    result.findings.append(
        _finding(
            "international_format",
            phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            1.0,
        )
    )

    region = phonenumbers.region_code_for_number(number)
    description = geocoder.description_for_number(number, "en")
    if region or description:
        result.findings.append(
            _finding(
                "region",
                f"{region} ({description})" if description else str(region),
                1.0,
                region_code=region,
                description=description,
            )
        )

    # Carrier is derived from the issuing block; number portability makes it go stale.
    carrier_name = carrier.name_for_number(number, "en")
    if carrier_name:
        result.findings.append(_finding("carrier", carrier_name, 0.8))

    line_type = _LINE_TYPES.get(phonenumbers.number_type(number), "unknown")
    result.findings.append(_finding("line_type", line_type, 1.0))

    for tz in timezone.time_zones_for_number(number):
        result.findings.append(_finding("timezone", tz, 1.0))

    return result
