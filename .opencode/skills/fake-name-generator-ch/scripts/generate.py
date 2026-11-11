#!/usr/bin/env python3
# ruff: noqa: S310, S311, T201
# - S310/S311: this is a stdlib-only CLI calling one fixed https URL and using
#   ``random`` for synthetic test data, not for anything security-bearing.
# - T201: the repo bans print() in application code; a CLI's whole job is stdout.
"""Generate a reproducible Swiss test-identity corpus from the Fake Name Generator API.

The API supplies the identity (name, address, phone, email, birthday) but no
Swiss national identifier: `country=ch` always returns `national_id: null`. This
script adds the two Swiss values the API cannot give, computed locally with
their real check digits:

* an AHV/AVS number (``756.xxxx.xxxx.xx``), 13 digits, EAN-13 check digit;
* a Swiss IBAN (``CHkk bbbb ...``), 21 characters, ISO 13616 mod-97 check.

Both are synthetic. They are valid by shape and check digit, which is what form
and DLP tests need, and they belong to nobody.

Reproducibility: the API guarantees that the same ``seed`` and the same
parameters replay the same identities (verified 2026-11-11), and the local
enrichment is seeded from ``(seed, index)``, so the same command regenerates the
same file. Keep ``fields`` fixed when regenerating: it is one of the parameters.
One identity costs one API credit (free pool: 100/day, resetting at 00:00 UTC),
which is why the committed corpus exists instead of generating per test run.

Usage
-----
    export FAKE_NAME_GENERATOR_API_KEY=fng_live_...      # or put it in .env
    python generate.py --seed bastion-swiss-v1 --out reference/swiss-corpus.jsonl
    python generate.py --check reference/swiss-corpus.jsonl
    python generate.py --stdout --count 2 --name-set french

The key is read from the environment first, then from the nearest ``.env``
walking up from this file. It is never printed.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Final

API_URL: Final[str] = "https://www.fakenamegenerator.com/api/v1/identities"
ENV_VAR: Final[str] = "FAKE_NAME_GENERATOR_API_KEY"
DEFAULT_OUT: Final[Path] = (
    Path(__file__).resolve().parent.parent / "reference" / "swiss-corpus.jsonl"
)

#: One API field set for every call. Seed replay is only promised for the same
#: parameters, and ``fields`` is one of them, so keep this list fixed.
FIELDS: Final[str] = (
    "id,name_set,country,name,gender,birthday,address,phone,email,username,occupation"
)

#: language region -> FNG ``name_set``. The API has no "swiss" name set; these
#: are the three national languages' sets, used as the closest available proxy.
REGIONS: Final[dict[str, str]] = {
    "de": "german",
    "fr": "french",
    "it": "italian",
}

#: A real Swiss bank clearing number, so the IBAN looks like a domestic one.
BANK_CLEARING: Final[str] = "00762"


class GenerateError(RuntimeError):
    """A fetch or validation failed; the message is safe to print."""


def load_api_key() -> str:
    """Return the API key from the environment or the nearest ``.env``."""
    import os

    key = os.environ.get(ENV_VAR, "").strip()
    if key:
        return key
    for parent in Path(__file__).resolve().parents:
        env_file = parent / ".env"
        if not env_file.is_file():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, sep, value = line.partition("=")
            if sep and name.strip() == ENV_VAR:
                return value.strip().strip("'\"")
    raise GenerateError(f"{ENV_VAR} is not set and no .env in a parent directory defines it")


def ahv_check_digit(first_twelve: str) -> str:
    """EAN-13 check digit over the first twelve AHV digits (weights 1,3,…)."""
    if len(first_twelve) != 12 or not first_twelve.isdigit():
        raise ValueError("AHV body must be twelve digits")
    total = sum(
        int(digit) * (1 if position % 2 == 0 else 3) for position, digit in enumerate(first_twelve)
    )
    return str((10 - total % 10) % 10)


def ahv_number(rng: random.Random) -> str:
    """A synthetic AHV/AVS number with a valid check digit."""
    body = "756" + "".join(str(rng.randrange(10)) for _ in range(9))
    number = body + ahv_check_digit(body)
    return f"{number[:3]}.{number[3:7]}.{number[7:11]}.{number[11:]}"


def iban_check_digits(bban: str, country: str = "CH") -> str:
    """ISO 13616 check digits for ``country`` + ``bban``."""
    letters = "".join(str(int(char, 36)) for char in country + "00")
    remainder = int(bban + letters) % 97
    return f"{98 - remainder:02d}"


def ch_iban(rng: random.Random) -> str:
    """A synthetic Swiss IBAN with a valid mod-97 check."""
    account = "".join(str(rng.randrange(10)) for _ in range(12))
    bban = BANK_CLEARING + account
    check = iban_check_digits(bban)
    compact = f"CH{check}{bban}"
    return " ".join(compact[i : i + 4] for i in range(0, len(compact), 4))


def is_valid_ahv(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not digits.startswith("756") or len(digits) != 13:
        return False
    return ahv_check_digit(digits[:12]) == digits[12]


def is_valid_ch_iban(value: str) -> bool:
    compact = value.replace(" ", "").upper()
    if not compact.startswith("CH") or len(compact) != 21 or not compact[2:].isalnum():
        return False
    return iban_check_digits(compact[4:]) == compact[2:4]


def fetch(
    *,
    api_key: str,
    name_set: str,
    count: int,
    seed: str | None,
    invalid: str | None,
    invalid_rate: float | None,
    timeout: float = 30.0,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Call ``GET /identities`` for Switzerland and return the data and headers."""
    params: dict[str, str] = {
        "country": "ch",
        "name_set": name_set,
        "count": str(count),
        "fields": FIELDS,
    }
    if seed is not None:
        params["seed"] = seed
    if invalid is not None:
        params["invalid"] = invalid
        if invalid_rate is not None:
            params["invalid_rate"] = str(invalid_rate)
    request = urllib.request.Request(
        f"{API_URL}?{urllib.parse.urlencode(params)}",
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
            headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise GenerateError(f"API returned {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise GenerateError(f"API unreachable: {exc.reason}") from exc

    data = payload.get("data")
    if not isinstance(data, list) or not data:
        raise GenerateError("API returned no identities")
    for header in ("credits-free-remaining", "credits-balance", "ratelimit"):
        if header in headers:
            print(f"{header}: {headers[header]}", file=sys.stderr)
    return data, headers


def enrich(identity: dict[str, Any], *, seed: str, index: int) -> dict[str, Any]:
    """Add the Swiss values the API does not supply, deterministically."""
    rng = random.Random(f"{seed}:{index}")
    record = dict(identity)
    record["language_region"] = {value: key for key, value in REGIONS.items()}.get(
        str(record.get("name_set")), "de"
    )
    record["ahv_number"] = ahv_number(rng)
    record["iban"] = ch_iban(rng)
    return record


def build(
    *,
    api_key: str,
    count_per_region: int,
    seed_base: str,
    invalid: str | None = None,
    invalid_rate: float | None = None,
) -> list[dict[str, Any]]:
    """Fetch one batch per language region and enrich every identity."""
    records: list[dict[str, Any]] = []
    for region, name_set in REGIONS.items():
        seed = f"{seed_base}-{region}"
        data, _headers = fetch(
            api_key=api_key,
            name_set=name_set,
            count=count_per_region,
            seed=seed,
            invalid=invalid,
            invalid_rate=invalid_rate,
        )
        for index, identity in enumerate(data):
            records.append(enrich(identity, seed=seed, index=index))
    return records


def check(records: Iterable[dict[str, Any]]) -> int:
    """Validate every record; return the number of failures."""
    failures = 0
    for number, record in enumerate(records, 1):
        problems: list[str] = []
        if record.get("country") != "ch":
            problems.append(f"country={record.get('country')!r}")
        if not is_valid_ahv(str(record.get("ahv_number", ""))):
            problems.append("AHV check digit")
        if not is_valid_ch_iban(str(record.get("iban", ""))):
            problems.append("IBAN mod-97")
        address = record.get("address") or {}
        if not address.get("postal_code") or not address.get("lines"):
            problems.append("address incomplete")
        if problems:
            failures += 1
            print(f"FAIL {number} {record.get('id', '?')}: {', '.join(problems)}")
    return failures


def write_jsonl(records: Sequence[dict[str, Any]], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a reproducible Swiss test-identity corpus "
        "(FNG API + local AHV/IBAN).",
    )
    parser.add_argument(
        "--count", type=int, default=4, help="identities per language region (1-100)"
    )
    parser.add_argument(
        "--seed",
        default="bastion-swiss-v1",
        help="seed base; each region derives '<seed>-<de|fr|it>' (default: bastion-swiss-v1)",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output JSONL path")
    parser.add_argument("--stdout", action="store_true", help="write to stdout instead of --out")
    parser.add_argument(
        "--invalid",
        default=None,
        help="comma-separated API defect names (email.any, phone.too_short, birthday.future, any)",
    )
    parser.add_argument(
        "--invalid-rate", type=float, default=None, help="share of defective identities (0-1)"
    )
    parser.add_argument(
        "--check",
        nargs="?",
        const=DEFAULT_OUT,
        type=Path,
        default=None,
        help="validate an existing JSONL corpus (default: the committed one)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.check is not None:
        records = [
            json.loads(line)
            for line in args.check.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        failures = check(records)
        if failures:
            print(f"FAILED: {failures} of {len(records)} records are invalid")
            return 1
        print(f"OK: {len(records)} records, AHV check digits and IBAN mod-97 valid")
        return 0

    if not 1 <= args.count <= 100:
        print("--count must be between 1 and 100", file=sys.stderr)
        return 2
    if args.invalid_rate is not None and not 0.0 <= args.invalid_rate <= 1.0:
        print("--invalid-rate must be between 0 and 1", file=sys.stderr)
        return 2

    try:
        records = build(
            api_key=load_api_key(),
            count_per_region=args.count,
            seed_base=args.seed,
            invalid=args.invalid,
            invalid_rate=args.invalid_rate,
        )
    except GenerateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.stdout:
        for record in records:
            print(json.dumps(record, ensure_ascii=False))
    else:
        write_jsonl(records, args.out)
        print(f"wrote {len(records)} identities to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
