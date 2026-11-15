### IDEA-057: Record the Vault dev overlay in an ADR and reconcile it with IDEA-020

- status: inbox
- priority: P2
- phase: v0.3
- area: docs
- tags: adr, secrets, vault, decision-record
- depends-on: -
- spec: -
- created: 2026-11-14
- updated: 2026-11-14
- source: review of the vault-secrets-overlay branch (PR #42, unmerged) against AGENTS.md "A decision → the ADR that records it"

**Problem**

The `vault-secrets-overlay` branch adds `docker-compose.vault.yml`, `vault/Dockerfile`, `vault/config.hcl`, six ACL policies under `vault/policies/`, `vault/bootstrap.py` and `README-Vault.md`: two new services (`vault`, `vault-bootstrap`), a self-signed TLS listener on 8200 beside the raft cluster listener on 8201, a fixed root token `dev-root-token-bastion`, an unseal key written to `/vault/data/unseal.key` inside the data volume, and a KV v2 mount named `bastion/`. `docs/adr/` holds 20 ADRs and none of them records any of it; `scripts/check_adrs.py` passes because it validates index and file shape, not whether a new decision needs a record, so the gap is invisible to the gate. `AGENTS.md` says "A decision → the ADR that records it", and a fixed root token plus on-disk unseal material is exactly the kind of decision that must not stay implicit in a compose overlay and a README.

The collision with `IDEA-020` is the reason this cannot wait for the production work. That item plans OpenBao with AppRole auth and states in its Notes that its ADR "must be written before code because it owns three choices the implementation cannot make implicitly": dev mode versus Shamir shares, SDK versus sidecar, and which identity `worker` gets. The unmerged dev overlay has already answered all three by accident — dev mode, a fixed root token, an unseal key on disk, six per-service policies — for dev only, with no record, while `SECURITY.md:255` and `COMPLIANCE.md:84` still say "use HashiCorp Vault or Azure Key Vault" as if it were a future option and `THREAT_MODEL.md` T4/T6 still describe environment-only secrets.

**Outcome**

A numbered ADR exists in `docs/adr/` with its `ADR-Index.md` row, and it is the single record of the Vault dev overlay: the mechanism (HashiCorp Vault on raft integrated storage, single node, TLS listener 8200 with cluster listener 8201, KV v2 at `bastion/`, one ACL policy per service, the `vault` and `vault-bootstrap` containers, non-root `vault` user, `cap_drop: ALL` with `cap_add: IPC_LOCK`, read-only rootfs, loopback-bound API port, additive overlay that leaves `docker-compose.yml` unchanged) and the explicit statement that the fixed root token, the unseal key on disk, the self-signed certificate with `VAULT_SKIP_VERIFY` and the single raft node are dev-only limits rather than a production posture. `IDEA-020` points at the ADR from its own body so the OpenBao plan is a successor decision, not a silent contradiction, and `grep -rn "HashiCorp Vault" SECURITY.md COMPLIANCE.md` stops reading as a promise the tree does not keep.

**Acceptance**

- [ ] `docs/adr/ADR-<next free>.md` exists with the required shape (`# ADR-XXX: <Title>`, the `**Status:**` / `**Date:**` / `**Last modified:**` block, a `## Context` of at least two paragraphs, a numbered `## Decision`, `## Consequences` with `**Pros**` and `**Cons**`), its row is in `docs/adr/ADR-Index.md` in numeric order, and `uv run python scripts/check_adrs.py` passes
- [ ] The ADR's `## Decision` names the mechanism concretely enough to be checked mechanically: `grep -in "raft\|8200\|8201\|bastion/\|KV v2\|cap_drop\|IPC_LOCK\|non-root\|vault-bootstrap" docs/adr/ADR-<n>.md` shows each term, and the ADR states that the overlay adds services without modifying any service in `docker-compose.yml`
- [ ] The ADR carries an explicit limits section stating that `dev-root-token-bastion`, `/vault/data/unseal.key`, the self-signed certificate and the single raft node are dev-only and must not be read as a production posture; `grep -in "dev-only\|fixed root token\|unseal" docs/adr/ADR-<n>.md` shows the fixed token and the unseal key named, and the `**Status:**` line is `Proposed` while the overlay is unmerged (flip it to `Accepted` in the change that merges it, and bump `Last modified`)
- [ ] The ADR distinguishes its Vault from the PII token vault: `grep -in "TokenVault\|token vault\|ADR-002" docs/adr/ADR-<n>.md` shows the disambiguation, so no later reader takes "the vault" to mean `agent/dlp/vault.py`
- [ ] `backlog/items/IDEA-020-*.md` gains one `**Notes**` line citing the new ADR as the decision the production design supersedes or extends, with `- updated:` bumped, and no other line of that item changes
- [ ] `grep -rn "HashiCorp Vault" SECURITY.md COMPLIANCE.md` returns only lines that describe the shipped overlay or label the production claim as planned, and neither file claims a production secret manager that only exists behind a dev overlay

**Notes**

- Dedupe: grepped `backlog/items/`, `BACKLOG.md` and `docs/adr/` for `vault`, `vault overlay`, `docker-compose.vault`, `hashicorp`, `openbao` and `approle`. Nothing covers this. `IDEA-020` is the production implementation (OpenBao, AppRole, KV reads, audit, rotation) and is `P2`/`v0.5`/`security`; this item is the missing decision record for what is already written plus the reconciliation of three documents, which is why it is not a Notes line on IDEA-020 — different deliverable, different phase, different area. The branch name `backlog/vault-overlay-gaps` exists locally but holds no commits of its own, so it is not a competing capture. `IDEA-001`, `IDEA-009` (which authored ADR-014) and `IDEA-016`/`IDEA-029` (payload escrow) are adjacent only.
- `spec: -` is deliberate: no Accepted ADR governs secret storage at all. This item authors that decision rather than implementing one, so forcing a reference to `ADR-002` (PII token vault), `ADR-001` (ingress auth) or `ADR-008` (phase scope) would misstate what governs it.
- Merger-relevant state: the overlay is unmerged (PR #42). The ADR must therefore be `Proposed` and must not be cited from `SECURITY.md`/`COMPLIANCE.md` as shipped behaviour until the merge lands, otherwise the documents claim a control master does not run. If PR #42 is closed unmerged instead, this item becomes the record of a rejected option and the acceptance still holds — the ADR then says so.
- The overlay is additive and dev-shaped in a second way the ADR must not blur: `make vault-export` materialises the values into a gitignored `.env.vault`, so secrets still reach the app containers through the environment for dev. That is a dev convenience, not the fail-closed provider `IDEA-020` designs; the ADR must say so, or a reader will take the overlay as partial delivery of IDEA-020.
- Scope: intake only. No ADR, document, compose or item edit is part of this capture.
