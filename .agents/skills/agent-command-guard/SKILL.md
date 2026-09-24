---
name: agent-command-guard
description: >-
  Release branching, pre-commit verification, and CI troubleshooting for
  agent-command-guard. Use when committing, opening PRs, cutting releases,
  or when CI fails on gofmt, golangci-lint, or Go version mismatch.
---

# agent-command-guard

Project-specific workflow for this repo. Also see `AGENTS.md` for layout and hook-change benchmarks.

## Pre-commit verification (required)

Run **before every commit**. Do not push until these pass.

```sh
# Go — mirrors CI job `go`
gofmt -l .                    # must print nothing
go vet ./...
go test ./...
go test -race ./...

# Build
./scripts/build.sh
wc -c build/agent-command-guard

# Pi adapter — mirrors CI job `pi`
bun --cwd adapters/pi test
bun --cwd adapters/pi exec bunx tsc --noEmit
```

Optional locally (CI runs these; local golangci-lint version may differ from CI v2.13):

```sh
golangci-lint run ./...
govulncheck ./...
```

If `main.go` or `cursor.go` changed, follow `AGENTS.md` **Hook Change Discipline**: benchmark + binary size before and after.

## CI layout

File: `.github/workflows/ci.yml`

| Job | Go | What it runs |
| --- | --- | --- |
| `go` | **1.27 only** | gofmt, vet, test, race, golangci-lint v2.13, govulncheck |
| `pi` | 1.27 | build, `bun test`, `tsc --noEmit` |
| `benchmark` | 1.27 | `./scripts/benchmark.sh`, binary size |

**Do not add Go 1.26** to CI. `go.mod` requires Go 1.27; with `GOTOOLCHAIN=local` the 1.26 job fails at `go vet`.

Release builds on tag push `v*` via `.github/workflows/release.yml`.

## Known CI failures

| Symptom | Fix |
| --- | --- |
| `gofmt diff: policy.go` | `gofmt -w policy.go` (or `gofmt -w .`) before commit |
| `go.mod requires go >= 1.27 (running go 1.26…)` | Remove 1.26 from CI matrix; project targets 1.27 |
| `func detect*… is unused (unused)` | After cwd-aware refactors, delete thin wrappers that only call `*InCwd(..., "")` — callers use `*InCwd` directly |
| `go (1.27)` cancelled | Usually fail-fast after another matrix leg failed; fix the first red job |

Check PR CI: `gh pr checks <number>`.

## Release branching

- `main` — latest **released** baseline (currently `v1.0.0`).
- `release/v1.1.0` — in-progress release (embedded `config/policy.json`, overlay merge, policy benches, README policy docs). Notes in `docs/config-extraction-experiments.md`.

```sh
git checkout release/v1.1.0   # feature work for 1.1.0
# when ready: merge to main, tag v1.1.0, push tag → release workflow
```

Move unreleased commits off `main` onto `release/<version>`; reset `main` to `origin/main` (prefer `git update-ref refs/heads/main origin/main` if hooks block `git reset --hard`).

## Pull requests

- Target: `release/v1.1.0` → `main` for the 1.1.0 release.
- Use `--draft` when asked.
- PR body: **Summary only** unless the user asks for more — no commit list after squash, no test plan unless requested.
- Squash to one commit when asked: `git reset --soft main && git commit && git push --force-with-lease`.
- Push branch before `gh pr create --draft --base main --head release/v1.1.0`.

## Quick verify (hook smoke)

```sh
printf '{"tool_name":"Bash","tool_input":{"command":"true"}}' | ./build/agent-command-guard; echo $?
printf '{"tool_name":"Bash","tool_input":{"command":"node -e \"x\""}}' | ./build/agent-command-guard
```
