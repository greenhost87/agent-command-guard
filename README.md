# Agent Command Guard

Opinionated command-policy guard for coding agents — **Codex**, **Cursor**, **Pi**. Inspects shell commands before execution, blocks risky patterns. Heuristic guard, not a sandbox.

## Requirements

- Go 1.27+, Bun 1.4+ (only for Pi adapter in `adapters/pi`)
- macOS arm64 tested. Linux works for policy, but install-confirmation (`osascript`) is macOS-only (other platforms fail closed).

## Install

From source checkout:

```sh
./install.sh                 # all harnesses (TTY prompts, non-TTY → all)
./install.sh --codex --cursor --pi
./install.sh --codex         # only Codex
```

Bootstrap without checkout:

```sh
curl -fsSL https://raw.githubusercontent.com/greenhost87/agent-command-guard/main/install.sh | bash
curl -fsSL https://raw.githubusercontent.com/greenhost87/agent-command-guard/main/install.sh | bash -s -- --codex
```

What it does: builds `build/agent-command-guard`, installs canonical binary to `~/.agent-command-guard/agent-command-guard` (same dir as daily logs `~/.agent-command-guard/*.jsonl`) and wires `~/.codex/hooks.json` / `~/.cursor/hooks.json` to that binary (backs up to `*.bak.*`). Pi adapter is installed to `~/.agent-command-guard/pi/` (`extension.ts` + `package.json`) and wired via `~/.pi/agent/settings.json` `packages` → `~/.agent-command-guard/pi` — no `~/develop` reference needed. Dev fallback `pi -e ./adapters/pi/extension.ts` still works.

## Policy

Decisions are **allow** or **deny** only. There is no harness-level “ask the agent UI” mode. Deny returns a reason to the agent (`permissionDecisionReason` / Cursor `agent_message`).

**Ask the human (macOS only):** install-class commands show an `osascript` dialog — `brew install|reinstall|upgrade|bundle`, `pip install` / `python -m pip install`, and `curl|wget … | sh|bash|…` installer pipes. Allow → continue (installer pipes may also skip the pipe-to-interpreter deny). Cancel / no `osascript` → deny.

**Denied:** inline interpreter (`node -e`, `python3 -c`, `bash -c`, `xargs … sh -c`, backtick/`$(...)` substitution, `env -S`, `eval`, pipe-to-interpreter, `find -exec sh -c`), interpreter stdin/heredoc, interactive REPLs, audit-script deletion (`.codex/tmp-scripts`), deletion outside workspace (`/`, `~/`, `../`), remote transfer (`ssh/scp/sftp/rsync/ftp/lftp`), agent transcripts / `~/.agent-quality-gate`, edits to `config/policy.json` outside this repo, destructive git (`clean` / `reset --hard` / `checkout --`), `rtk run`.

**Allowed:** normal build/test, plain `curl`/`find` without the patterns above, scoped Cursor `grep`/`glob`, quoted literals (`echo 'python3 -c ...'`).

Policy tables live in embedded `config/policy.json` (optional `ACG_POLICY_CONFIG` overlay). Details in `main.go` / `cursor.go` / `policy.go`.

## Verify

```sh
printf '{"tool_name":"Bash","tool_input":{"command":"true"}}' | ./build/agent-command-guard; echo $?
printf '{"tool_name":"Bash","tool_input":{"command":"node -e \"x\""}}' | ./build/agent-command-guard
bun --cwd adapters/pi test
```

## Uninstall

```sh
rm -f ~/.agent-command-guard/agent-command-guard
rm -rf ~/.agent-command-guard/pi
# edit ~/.codex/hooks.json, ~/.cursor/hooks.json, ~/.pi/agent/settings.json to remove entries
# legacy: rm -f ~/.codex/hooks/agent-command-guard ~/.cursor/hooks/agent-command-guard
```

## Limitations

Text inspection only — aliases, custom binaries, symlinks, `PATH` tricks may bypass. Lexical path checks don't resolve filesystem. Not a security boundary.

## License

MIT — see `LICENSE`. Unofficial, not affiliated with OpenAI (Codex) or Pi.
