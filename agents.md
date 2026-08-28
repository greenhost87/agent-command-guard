# Project Notes For Agents

## Layout

- `main.go` is the shared command-policy engine and the Codex PreToolUse stdin/stdout protocol.
- `cursor.go` is the Cursor adapter: `beforeShellExecution` over the shared engine, plus `preToolUse` policy for unconstrained `grep`/`glob`. Cursor tests live in `cursor_test.go`.
- `adapters/pi/extension.ts` is the Pi adapter; it invokes `build/agent-command-guard`.
- `adapters/pi/host.ts` is the Pi test host helper.
- `adapters/pi/extension.test.ts` loads that adapter through Pi's `DefaultResourceLoader` and `emitToolCall`. It never creates an agent session or calls a model.
- `adapters/pi/` is the only TypeScript: `extension.ts` (Pi adapter), `host.ts` (test host), `extension.test.ts`, `benchmark.ts`, `install.ts` (Pi instructions), plus `package.json`/`bun.lock`/`bunfig.toml`/`node_modules` isolated there.
- `cmd/install` is the Go installer for Codex/Cursor/Pi (`go run ./cmd/install`); it builds `build/agent-command-guard`, copies to `~/.codex/hooks/` / `~/.cursor/hooks/` and merges `hooks.json` atomically.
- `.codex/tmp-scripts/` is the audit directory the policy requires for temporary interpreter scripts.

## Commands

```sh
go test .
bun --cwd adapters/pi test
./scripts/build.sh
./scripts/install.sh
./scripts/benchmark.sh
./scripts/benchmark-pi.sh
```

`bun --cwd adapters/pi test` builds `build/agent-command-guard` and exercises the Pi `tool_call` path locally: isolated temp dirs, `PI_OFFLINE=1`, no `createAgentSession`, no provider calls. `benchmark-pi.sh` reports `go_direct`, `pi_full`, and paired `ts_wrap = pi_full - go_direct` (TypeScript/Pi adapter overhead above the Go process). `benchmark.sh` still measures Go spawning the hook directly. TS package is isolated in `adapters/pi` (`adapters/pi/package.json`, `bun.lock`, `bunfig.toml`).

`./scripts/install.sh` builds once and installs into both `~/.cursor/hooks/` and `~/.codex/hooks/` by default (`all`). Pass `cursor` or `codex` for a single harness. It also configures the corresponding `hooks.json` (`~/.cursor/hooks.json`, `~/.codex/hooks.json`) idempotently, backing up any existing file to `hooks.json.bak.<timestamp>` first. Install logic lives in `cmd/install` (`go run ./cmd/install`).

## Hook Change Discipline

Changes to `main.go` or `cursor.go` follow this sequence:

1. Measure the current baseline:

   ```sh
   ./scripts/benchmark.sh
   wc -c build/agent-command-guard
   ```

2. Make the change.

3. Run `go test .`

4. Measure again with the same benchmark shape:

   ```sh
   ./scripts/benchmark.sh
   wc -c build/agent-command-guard
   ```

Report the before/after binary size and benchmark numbers when finishing the change.

Changes to `adapters/pi/extension.ts` follow this sequence:

1. Run `bun --cwd adapters/pi test`
2. Run `./scripts/benchmark-pi.sh`

## Releases

- `main` — tracks the latest released baseline (`v1.0.0`).
- `release/v1.1.0` — next release branch; policy tables moved to embedded `config/policy.json` with `ACG_POLICY_CONFIG` overlay merge, production-path policy benches, and README allow/deny vs install-confirmation docs. Experiment notes in `docs/config-extraction-experiments.md`.

Work on 1.1.0 from the release branch:

```sh
git checkout release/v1.1.0
```

Merge to `main` and push tag `v1.1.0` when the release is ready (`.github/workflows/release.yml` builds on `v*` tags).
