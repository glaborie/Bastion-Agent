### IDEA-086: Self-host CI runners and evaluate Gitea

- status: active
- priority: P2
- phase: v0.5
- area: infra
- tags: ci, github-actions, git, supply-chain
- depends-on: -
- spec: -
- created: 2026-11-19
- updated: 2026-11-20
- source: session 2026-11-19, prompted by IDEA-025's record of the 2026-11-11 GitHub runner incident and ADR-016 decision 5's ~6.5 min billed runner cost per scan

**Problem**

Every job in the pipeline depends on GitHub-hosted capacity. All six jobs in
`.github/workflows/ci.yml` (`changes` :33, `quality` :65, `tests` :138, `evals`
:281, `supply-chain` :357, `ci-ok` :434) and `.github/workflows/wiki-sync.yml:25`
run on `runs-on: ubuntu-latest`, and no runner, act_runner or Gitea service
exists in `docker-compose.yml`. That makes the merge-blocking gate dependent on
a third party: IDEA-025 had to land image evidence from a local run because
"pull request runs were abandoned on 2026-11-11 while GitHub runners were
failing", and ADR-016 decision 5 narrowed the scan cadence because one scan
costs about 6.5 minutes of billed runner time. The expensive jobs are exactly
the ones where hosted limits bite: `supply-chain` runs Docker and `docker save`
through `scripts/scan_images.sh`, `evals` downloads real ONNX models
(`ci.yml:304-333`), and `tests` needs Postgres, Redis and the MinIO witness as
service containers (`ci.yml:145-190`).

**Outcome**

One recorded decision on where CI executes, with the heavy jobs able to run on
a controlled host if that is the choice and every job that stays hosted saying
why. If a self-hosted runner is chosen, it is a documented service or install
with a stable label the workflows target, its image (when containerised) enters
the ADR-016 inventory, and it never executes fork pull-request code without the
isolation the decision describes. The Gitea/act_runner alternative gets a
written verdict in the same record, including what migrating the forge would
cost: branch protection, `.github/` workflows, repo secrets, the `gh`-based PR
flow and the pushed-branch claim protocol in `scripts/dev/worktree.sh`.

**Acceptance**

- [ ] An ADR in `docs/adr/` records the runner-hosting decision and the Gitea verdict, and `uv run python scripts/check_adrs.py` passes
- [ ] `grep -n "runs-on" .github/workflows/*.yml` shows every job either targeting the documented runner label or deliberately staying `ubuntu-latest` for a reason the record states
- [ ] If a runner joins the stack, `uv run python scripts/image_inventory.py` lists its image and `./scripts/scan_images.sh --build-missing` still exits 0
- [ ] The pull-request security position is written down: whether self-hosted runners are safe for this repository (private repo versus fork PRs) and what is gated off if not
- [ ] Any `COMPLIANCE.md` or `THREAT_MODEL.md` row that names CI changes with it, and `uv run python scripts/check_threat_model.py` passes

**Notes**

- `spec: -` because no ADR records CI hosting today; the first acceptance box is
  the decision that would become the governing one. Related but not duplicate:
  IDEA-008 (bit-reproducible eval gate across hosted runners) fixes the runner
  image's effect on eval scores and must be revisited if runners move; IDEA-019
  and IDEA-025 record hosted-runner cost and an outage, not where CI executes.
- Deliberately not captured here: migrating the forge to Gitea/Forgejo is a
  separate decision with its own blast radius (branch protection, PR automation,
  `gh` usage, the worktree claim via pushed branches). This item only requires a
  written verdict; a "migrate" verdict becomes a follow-up item.
- Open questions for triage: is the repository private (self-hosted runners on a
  public repo execute untrusted fork code unless the workflow is approval-gated);
  is the eval job's target the GPU host or plain CPU; is the goal cost,
  reliability or data residency — each points at a different answer; and should
  a runner be a profile-gated, digest-pinned compose service per ADR-016 or an
  operator-installed daemon outside the stack.
