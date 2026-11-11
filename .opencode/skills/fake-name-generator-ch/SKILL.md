---
name: fake-name-generator-ch
description: Generate Swiss test identities and a reproducible PII corpus from the Fake Name Generator API — names, addresses, phones and emails for the German, French and Italian regions, plus locally computed AHV/AVS numbers and Swiss IBANs with valid check digits. Use when seeding forms, databases or DLP tests with Swiss personal data.
compatibility: claude-code, cursor, codex, github-copilot, opencode
---

# Swiss test identities (Fake Name Generator API)

Generate synthetic Swiss people for form validation, database seeding and DLP
testing. The API supplies the identity; the two Swiss identifiers it does not
supply — AHV/AVS number and IBAN — are computed locally with their real check
digits.

Everything below was verified against the live API on 2026-11-11. The contract
is also written down in `reference/api-notes.md`; the committed corpus is
`reference/swiss-corpus.jsonl` and the generator is `scripts/generate.py`.

## Quick start

```bash
export FAKE_NAME_GENERATOR_API_KEY=fng_live_...     # also read from the repo .env

# Regenerate the committed corpus. --count is per region, so this is
# 12 identities: 4 German, 4 French, 4 Italian. Without --out it writes
# .opencode/skills/fake-name-generator-ch/reference/swiss-corpus.jsonl
python .opencode/skills/fake-name-generator-ch/scripts/generate.py \
  --seed bastion-swiss-v1 --count 4

# Validate the committed corpus offline: no credits, no network
python .opencode/skills/fake-name-generator-ch/scripts/generate.py --check

# Validate a different file
python .opencode/skills/fake-name-generator-ch/scripts/generate.py \
  --check /tmp/swiss.jsonl

# A quick look without writing a file (3 regions x 2 = 6 identities)
python .opencode/skills/fake-name-generator-ch/scripts/generate.py \
  --stdout --count 2 --seed adhoc-1
```

Output is one JSON object per line: the API identity fields plus
`language_region`, `ahv_number` and `iban`.

Do not call the API per test run. One identity costs one credit (free pool:
100 per day per account, resetting at 00:00 UTC), so build the corpus once,
commit it, and use `--check` or the committed file afterwards.

## What you get, and what you do not

| Field | Swiss output |
|-------|--------------|
| `name` | localised by `name_set` (`german`, `french`, `italian`), with `title`, `middle_initial`, `mothers_maiden` |
| `address` | `street`, `city`, `postal_code` (4-digit), `lines`, `latitude`, `longitude`; `state` and `district` are **always `null`** |
| `phone` | `0xx xxx xx xx` with `country_code: "+41"` |
| `email` | on `teleworm.us`, `jourrapide.com`, `armyspy.com` or `dayrep.com` |
| `birthday` | `date` (`YYYY-MM-DD`) and `age` |
| `gender`, `username`, `occupation` | present when requested in `fields` |
| `national_id` | **`null` for every Swiss identity** |
| AHV/AVS number | not supplied — generated locally by `scripts/generate.py`, valid EAN-13 check digit |
| Swiss IBAN | not supplied — generated locally, valid ISO 13616 mod-97 check, clearing number `00762` |
| Canton | not supplied and not derivable from the API — do not claim one |

## API contract

Base URL `https://www.fakenamegenerator.com/api/v1` (the bare domain 301s).
`GET /identities` with `Authorization: Bearer <key>`.

| Parameter | Value for Switzerland |
|-----------|-----------------------|
| `country` | `ch` (required for Swiss data; default is `us`) |
| `name_set` | `german`, `french` or `italian` — there is **no** `swiss` name set |
| `count` | 1–100, default 1, one credit each |
| `seed` | `^[A-Za-z0-9_-]{1,64}$`; the same seed **and the same parameters** replay the same identities |
| `fields` | comma-separated top-level fields; nested extras still arrive |
| `gender` | `random` (default), `male`, `female` |
| `min_age` / `max_age` | 0–100, defaults 19 / 85 |
| `invalid` | comma-separated defect names, `field.any`, or `any` |
| `invalid_rate` | share of identities to defect, 0–1, default 1 |

Response: `{"data": [ ... ]}`. Real Swiss identity (trimmed, 2026-11-11):

```json
{
  "data": [
    {
      "id": "70cfa266-3cdd-4eb8-9c44-8fc33cb3d3dd",
      "seed": null,
      "name_set": "german",
      "country": "ch",
      "name": {"title": "Ms.", "first": "Antje", "middle_initial": "T",
               "last": "Beich", "full": "Antje Beich", "mothers_maiden": "Eggers"},
      "gender": "female",
      "birthday": {"date": "1995-05-25", "age": 31},
      "address": {"street": "Kappelergasse 106", "city": "Aegerten", "state": null,
                  "postal_code": "4923", "district": null, "country_code": "CH",
                  "lines": ["Kappelergasse 106", "4923 Aegerten"],
                  "latitude": 47.266222, "longitude": 7.852261},
      "phone": {"number": "062 610 44 48", "country_code": "+41"},
      "email": "AntjeBeich@jourrapide.com",
      "national_id": null
    }
  ]
}
```

Headers to read on every call: `Credits-Free-Remaining`, `Credits-Balance`,
`Credits-Charged`, `RateLimit` (300 requests/minute), `Request-Id`. Errors are
RFC 9457 problems with a `code`: `invalid-parameter`, `unauthorized`,
`insufficient-credits` (402, nothing charged), `rate-limited`, `server-error`.

`GET /options` is free and lists every country, name set, field, validator and
defect — read it instead of guessing a code. `GET /account` reports the balance.

## Swiss caveats that matter for tests

- **No canton.** `address.state` is `null` and `/options` lists no states for
  `ch`. A test that needs a canton must add its own mapping, and must not
  pretend the API supplied it.
- **Street, city and language region are independent.** A German name can get
  `Via Camischolas sura` in Dietikon, or an Italian street in Ettiswil. Treat
  the address as shape-correct, not geography-correct.
- **Postcode and city are not guaranteed to be a real pair.** Do not use the
  corpus to test postal validation; use it to test parsing, redaction and
  form round-trips.
- **Names arrive transliterated.** `Kuester`, `Baumgaertner`, `Duerr`; city
  names keep their diacritics (`Hüswil`, `Chandolin-près-Savièse`). Both forms
  are useful: the first for ASCII pipelines, the second for UTF-8 and SQL
  collation.
- **Emails are on disposable-looking domains.** Fine for DLP and form tests,
  never for anything that sends mail.
- **`national_id` is always `null` for `ch`**, so no test should assert one.

## Invalid data

`invalid=` accepts comma-separated defects, `field.any`, or `any`. For `ch` the
applicable defects are the generic ones:

```
email.no_at  email.double_dot  email.space  phone.too_short
birthday.future  birthday.impossible_date  credit_card.*
```

The `national_id.check_digit` and `national_id.length` defects **do not apply to
`ch`** (see the `countries` list for each defect in `/options`), so a Swiss
identity can never come back with a broken national ID. Defective rows carry a
`defects` array naming what was broken.

```bash
python .opencode/skills/fake-name-generator-ch/scripts/generate.py \
  --stdout --count 4 --invalid email.any,phone.too_short --invalid_rate 0.5
```

## Validating values

The API's `POST /validate/{type}` has **no Swiss AHV validator**: `matricule` is
the Belgian NISS (it checks `birth_date`, `luhn`, `verhoeff`), and the other 38
types are other countries. Do not send an AHV number to it.

Validate locally instead:

```bash
python .opencode/skills/fake-name-generator-ch/scripts/generate.py --check
```

That re-computes the EAN-13 check digit of every AHV number and the mod-97 check
of every IBAN, and fails non-zero on any mismatch. The functions are importable
if a test wants them: `is_valid_ahv`, `is_valid_ch_iban`.

For this repository's DLP work: email, phone, street address and date of birth
are the fields the Presidio stage detects (`ADDRESS`, `DATE_OF_BIRTH`), and an
IBAN is detected as `IBAN_CODE`. AHV/AVS is **not** a recognizer yet (backlog
IDEA-013), so an AHV number in a prompt is not redacted — that is a real gap,
not a corpus defect.

## Security

- The key is `FAKE_NAME_GENERATOR_API_KEY`, read from the environment and then
  from the nearest `.env`. It is a bearer credential: never print it, never
  commit it, never pass it on a command line in a shared log.
- Generated data is synthetic, but treat it as PII in code paths: it exercises
  the same redaction, logging and retention controls as real records.
- The corpus is deterministic from `--seed`; do not "fix" a record by hand, fix
  the generator and regenerate.
