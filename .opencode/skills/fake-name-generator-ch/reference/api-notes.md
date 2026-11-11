# Fake Name Generator API — verified contract (2026-11-11)

Source of truth: `https://www.fakenamegenerator.com/api/v1/openapi.json`
(OpenAPI 3.1.0, "Fake Name Generator API 1.0.0"). This file records what the
live service actually does for Switzerland, including the places where the
OpenAPI description alone is not enough.

## Endpoint and auth

```
https://www.fakenamegenerator.com/api/v1
Authorization: Bearer fng_live_...
```

- `https://fakenamegenerator.com/...` and `https://api.fakenamegenerator.com/...`
  answer **301**; use the `www` host with the `/api/v1` prefix.
- The key is a bearer credential (`securitySchemes.apiKey`, `type: http`,
  `scheme: bearer`). In this repository it is `FAKE_NAME_GENERATOR_API_KEY`,
  set in `.env`.

## `GET /identities`

| Parameter | Type | Default | Notes |
|-----------|------|---------|-------|
| `count` | integer 1–100 | 1 | one credit per identity |
| `country` | ISO 3166, lowercase | `us` | `ch` for Switzerland; 75 values in `/options`; `cy-el`, `bg-cyrl`, `cn-hans` are script variants |
| `state` | string | — | a state/province; **`ch` has none** |
| `name_set` | enum, 95 values | `american` | `german`, `french`, `italian` are the closest Swiss proxies; there is no `swiss` |
| `gender` | `random` \| `male` \| `female` | `random` | |
| `min_age` / `max_age` | integer 0–100 | 19 / 85 | |
| `seed` | `^[A-Za-z0-9_-]{1,64}$` | — | same seed **and parameters** → same identities; echoed back |
| `card` | `random` \| `any` \| `stripe` \| `braintree` \| `paypal` \| `adyen` \| `square` \| `authorizenet` \| `checkout` | `random` | test cards for that processor |
| `fields` | comma-separated top-level fields | all | one or more of `id, seed, name_set, country, name, gender, birthday, address, phone, email, username, password, national_id, credit_card, occupation, company, vehicle, website, height, weight, blood_type, favorite_color, user_agent, zodiac_sign, portrait` |
| `invalid` | comma-separated defects, `field.any`, or `any` | — | see "Defects" |
| `invalid_rate` | number 0–1 | 1 | share of identities that get a defect |

`from`/`size` do not exist; paging is `count` only.

### Response

`200 application/json`, `{"data": [Identity, …]}`. `Identity` (schema name)
carries: `id` (uuid), `seed`, `name_set`, `country`, `name` (`title`,
`first`, `middle_initial`, `last`, `full`, `mothers_maiden`), `gender`,
`birthday` (`date` `YYYY-MM-DD`, `age`), `address` (`street`, `city`, `state`,
`postal_code`, `district`, `country_code`, `lines[]`, `latitude`, `longitude`),
`phone` (`number`, `country_code`), `email`, `username`, `password`,
`national_id` (`null` or `{type, value}`), `credit_card` (`network`, `number`,
`expires`, `cvv`, `test_card_for`), `occupation`, `company`, `vehicle`,
`website`, `height`, `weight`, `blood_type`, `favorite_color`, `user_agent`,
`zodiac_sign`, `portrait`, and `defects[]` when `invalid` was used.

`fields` filters **top-level** keys only: asking for `name` also returns
`middle_initial` and `mothers_maiden`, and asking for `address` also returns
`district`, `latitude` and `longitude`.

### Headers

| Header | Meaning |
|--------|---------|
| `Credits-Free-Remaining` | free credits left today (UTC) |
| `Credits-Balance` | paid credits left |
| `Credits-Charged` | paid credits this request consumed (free credits are not counted) |
| `RateLimit` | draft-ietf-httpapi-ratelimit-headers, e.g. `"key";r=298;t=35` |
| `RateLimit-Policy` | `"key";q=300;w=60` — 300 requests per minute |
| `Request-Id` | support reference |

### Errors

RFC 9457 problem objects: `type`, `title`, `status`, `code`, optional
`detail`, `parameter`, `request_id`. Codes: `invalid-parameter`,
`unauthorized`, `insufficient-credits` (HTTP 402; per the spec **nothing is
charged** when the request cannot be paid for in full), `not-found`,
`method-not-allowed`, `rate-limited`, `server-error`.

## Switzerland, measured

Live calls on 2026-11-11, `country=ch`:

- `national_id` was **`null` on every identity**, under `german`, `french` and
  `italian` name sets.
- `address.state` and `address.district` were **`null`**; `/options` lists
  `states: []` for `ch`.
- `address.postal_code` is four digits and `address.lines` is
  `[street, "postcode city"]`.
- `phone.country_code` is `"+41"`; numbers are `0xx xxx xx xx`.
- Emails use `teleworm.us`, `jourrapide.com`, `armyspy.com`, `dayrep.com`.
- Names come transliterated (`Kuester`, `Baumgaertner`, `Duerr`) while city
  names keep diacritics (`Hüswil`, `Chandolin-près-Savièse`).
- Street, city and name set are independent: a German name got
  `Via Camischolas sura` in Dietikon, and an Italian street appeared in
  Ettiswil. Addresses are shape-correct, not geographically consistent.
- `seed` replay was verified: two requests with `seed=bastion-demo-1`,
  `country=ch`, `name_set=german`, `count=1` and the same `fields` returned the
  same `id` and name.
- Credits: `count=3` returned `credits-charged: 0`,
  `credits-balance: 0`, `credits-free-remaining: 97` — the free pool is used
  first, and it is 100 per day (`/options.limits`).

## `/options` and `/account` (free)

`GET /options` returns `countries` (75, each with `states`), `name_sets` (95),
`genders`, `fields` (25), `validators` (39), `defects` (12) and `limits`
(`max_count: 100`, `free_credits_per_day: 100`,
`free_validations_per_day: 1000`, `requests_per_minute: 300`).

`GET /account` reports the balance and is the cheapest way to check a key.

## `POST /validate/{type}`

Body `{"value": "..."}`; returns `{type, valid, normalized, checks, details}`.
Free allowance: 1,000 per day, then one credit each; values are not stored.

The 39 types are other countries' identifiers (`card`, `aba`, `vin`, `ssn`,
`sin`, `nino`, `cpf`, `curp`, `dni`, `pesel`, `cpr`, `hetu`, …). **`matricule`
is the Belgian NISS, not the Swiss AHV/AVS number**: it reports
`checks.birth_date`, `checks.luhn` and `checks.verhoeff`, and rejects
`756.1234.5678.97` and `756.1234.5678.90` alike. There is no Swiss AHV
validator here; validate locally (EAN-13 check digit over the first twelve
digits of `756xxxxxxxxx`).

## Defects

12 names. `credit_card.*`, `email.*`, `phone.too_short`, `birthday.*` apply to
every country (`countries: null`). `national_id.check_digit` and
`national_id.length` list their applicable countries explicitly, and **`ch` is
not among them** — a Swiss identity cannot be returned with a broken national
ID. `national_id.never_issued` is `us` only.
