### IDEA-004: Export the audit ledger asynchronously for retention

- status: ready
- priority: P2
- phase: v0.3
- area: db
- tags: audit, export, compliance, retention
- depends-on: IDEA-001
- spec: ADR-008
- created: 2026-11-09
- updated: 2026-11-09
- source: ADR-008, phase v0.3 scope

**Problem**

The hash-chained ledger only grows; compliance retention requires a
portable export, and an export without a tenant dimension would leak across
customers.

**Outcome**

A worker job writes signed, chain-verified segments to object storage
with a manifest, and verification can be rerun against an exported segment.

**Acceptance**

- [ ] Export job pages the ledger without breaking the hash chain
- [ ] Manifest records segment bounds and the terminal hash
- [ ] `scripts/verify_audit_chain.py` accepts an exported segment
- [ ] Retention and deletion policy documented in COMPLIANCE.md

**Notes**

- 2026-11-12 (IDEA-021): the immutable store and the out-of-band head witness ship separately. `--profile compliance` supplies MinIO with versioning and 7-year `COMPLIANCE` object lock, the witness-only credential, `scripts/write_audit_witness.py` and `scripts/verify_audit_chain.py --witness`. This item still owns the missing half: paging the ledger into signed segments, the manifest with bounds and terminal hash, and the retention/deletion policy text. The witness is a head anchor, not an export; do not mark these boxes from it.
