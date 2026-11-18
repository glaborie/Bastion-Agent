### IDEA-069: Notify once when the dashboard opens with handoffs already queued

- status: done
- priority: P2
- phase: v0.4
- area: gateway
- tags: dashboard, handoff, notifications
- depends-on: IDEA-065
- spec: ADR-022
- created: 2026-11-17
- updated: 2026-11-18
- source: session report on 2026-11-17 ("Alice logged on the dashboard with accepted notifications didn't receive any notification")

**Problem**

`gateway/dashboard/static/handoffs.js` primes its `sessionStorage` seen-set on the
first poll and deliberately stays silent for every row that was queued before the
page opened:

```js
// The first poll primes the set: rows that were already queued when the page
// opened are old news, so they do not arrive as a burst of notifications.
let primed = sessionStorage.getItem(seenKey) !== null;
```

That is a defensible default — twenty queued handoffs must not fire twenty
popups — but it reads as "notifications are broken" the moment an operator opens
the dashboard after someone escalated. Reported case: Alice signed in with
notifications granted, two handoffs were already queued (audit rows 752 and 763),
the panel listed both, and no notification arrived; the same silence covered the
next conversation (row 831-845) because that turn produced no handoff at all
(IDEA-070). The operator cannot tell "nothing new" apart from "the channel does
not work", which is exactly what the panel was added to fix.

**Outcome**

Opening the dashboard with handoffs already queued produces **one** notification
that says how many are waiting (and names the newest conversation id), never one
per row; opening it with an empty queue stays silent; and every handoff queued
while the tab is open notifies individually as today. No push service, no new
endpoint and no transcript text: the summary is built from the same
`data-handoff-*` attributes the fragment already carries. The behaviour is pinned
by a test that executes the shipped script against a stubbed DOM and
`Notification`, so the policy cannot silently drift back.

**Acceptance**

- [x] A fresh session whose first poll returns N > 0 rows raises exactly one notification, whose body carries the count and the newest conversation id and verdict, and no id per row
- [x] A fresh session with an empty first poll raises none, and a handoff queued between later polls still raises one (the current behaviour is preserved)
- [x] Repeat polls over the same rows raise nothing, and a session that already acknowledged the queue (`sessionStorage`) does not summarise again on the next page load
- [x] The policy is covered by a committed test that runs `gateway/dashboard/static/handoffs.js` under Node with a stub `document`, `sessionStorage` and `Notification` (skipped when Node is absent), asserting the three cases above
- [x] ADR-022 decision 8 is amended to state the first-load summary (it currently documents the silent priming) and README's handoff section matches
- [x] `scripts/gate.sh` is green

**Notes**

- Current code path: `handoffs.js` computes `primed` from `sessionStorage`, notifies only when `primed` is true, and tags each notification `bastion-handoff-<id>`; the seen-set keeps the last 200 ids. The summary needs its own tag (e.g. `bastion-handoff-queue`) so browsers coalesce repeat summaries but still show per-id notifications.
- Why not simply notify one popup per queued row: the queue holds up to twenty (`MAX_HANDOFF_RECORDS`) and a browser that fires twenty notifications gets muted by the OS, which loses the real-time signal as well. A count is the useful fact.
- Why not drop `sessionStorage` and notify every poll: same burst, once per page load, and it defeats the dedupe that keeps a 15-second poll quiet.
- Out of scope: e-mail/webhook/push delivery, per-queue acknowledgement, and any change to the handoff panel's rendering.
- Shipped: `handoffs.js` calls `scan()` once at load (an empty first poll still primes the seen-set), and the summary is tagged `bastion-handoff-queue` with the count, newest verdict and newest conversation id in the body. `tests/js/handoffs_harness.js` drives the shipped script in a Node `vm` context.
- Known limit, left alone: granting permission *after* the first poll (operator clicks **Enable browser alerts** on a queue already on screen) does not replay the summary, because the seen-set is primed by then. It needs a decision only if operators report it; today the panel itself shows the queue.
