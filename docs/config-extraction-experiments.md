# Configuration Extraction Experiments

Question: can hardcoded policy tables in `main.go` move into configuration files without losing performance?

Method per attempt:

1. Measure baseline with `./scripts/benchmark.sh` and `wc -c build/agent-command-guard`.
2. Make the change.
3. `go test .` must pass (169 tests).
4. Re-measure with the same benchmark shape and record results.

Benchmark = 300 iterations / 20 warmup of spawning the built hook with a fixed payload; numbers are milliseconds.

## Baseline (before any change)

Binary size: 1,755,010 bytes

| case | median | p95 | mean |
| --- | --- | --- | --- |
| baseline_spawn_true | 1.419 | 1.624 | 1.435 |
| ignored_non_shell_tool | 2.309 | 2.689 | 2.354 |
| allowed_simple_shell | 2.462 | 2.701 | 2.493 |
| allowed_typical_shell | 2.405 | 2.523 | 2.412 |
| allowed_workspace_script | 2.412 | 2.561 | 2.420 |
| denied_node_eval | 2.430 | 2.530 | 2.437 |
| denied_tmp_script_cleanup | 2.495 | 2.647 | 2.587 |
| allowed_patch_text_mentions_cleanup | 2.492 | 2.588 | 2.493 |
| denied_patch_delete_tmp_script | 2.491 | 2.623 | 2.517 |

## Attempt 1 - name-set tables to `config/policy.json`

What was moved: every hardcoded string-set switch/table in `main.go`:

- separators (`|`, `||`, `&&`, ...)
- shell keywords (`if`, `then`, ...)
- command wrappers (`command`, `sudo`, `rtk`, ...)
- shell tool names (`Bash`, `exec_command`, ...)
- patch tool names (`apply_patch`, `Edit`, `Write`)
- remote commands (`ssh`, `scp`, ...)
- interpreter sets: pipe interpreters, node interpreters, shell interpreters, python versioned prefixes

How: new `config/policy.json` + new `policy.go`. The config is embedded into the binary with `go:embed` as default and parsed at init by a minimal hand-rolled JSON scanner (reuses existing `scanJSONString`/`skipJSONValue`; no `encoding/json`). `ACG_POLICY_CONFIG=/path/to.json` overrides the embedded defaults at runtime without a rebuild. Switch statements became map lookups over read-only `map[string]struct{}` sets.

Result after change (`go test .`: 169 passed):

Binary size: 1,771,842 bytes (+16,832, +0.96%)

| case | median | p95 | mean | delta median vs baseline |
| --- | --- | --- | --- | --- |
| baseline_spawn_true | 1.404 | 1.509 | 1.412 | -0.015 |
| ignored_non_shell_tool | 2.326 | 2.440 | 2.334 | +0.017 |
| allowed_simple_shell | 2.488 | 2.643 | 2.510 | +0.026 |
| allowed_typical_shell | 2.501 | 2.646 | 2.515 | +0.096 |
| allowed_workspace_script | 2.492 | 2.908 | 2.556 | +0.080 |
| denied_node_eval | 2.465 | 2.698 | 2.493 | +0.035 |
| denied_tmp_script_cleanup | 2.470 | 2.691 | 2.505 | -0.025 |
| allowed_patch_text_mentions_cleanup | 2.446 | 2.650 | 2.469 | -0.046 |
| denied_patch_delete_tmp_script | 2.452 | 2.568 | 2.459 | -0.039 |

Verdict: viable. All deltas are inside run-to-run noise (baseline itself varies by ~±0.05 ms between cases). Init-time parse cost of ~800 B of JSON is unmeasurable next to process spawn (~1.4 ms). Binary grows ~17 KB from embedding the config text plus the tiny parser. Policy name lists are now editable without touching Go code.

## Attempt 2 - messages, markers and `scriptDir` to `config/policy.json`

What was moved: all user-facing policy strings that were Go constants:

- `scriptDir` (`.codex/tmp-scripts`) and the shared guidance sentence
- inline / stdin / interactive interpreter block reasons
- `agent-transcripts` marker + reason
- `.agent-quality-gate` marker, cwd token + reason

How: new `messages` section in `config/policy.json`; the constants became package vars populated once at init from the parsed config (same embedded-defaults + `ACG_POLICY_CONFIG` override mechanism as attempt 1; no extra I/O at request time).

Result after change (`go test .`: 169 passed):

Binary size: 1,771,922 bytes (+80 vs attempt 1, +0.005%; +16,912 vs baseline)

| case | median | p95 | mean | delta median vs attempt 1 |
| --- | --- | --- | --- | --- |
| baseline_spawn_true | 1.409 | 1.643 | 1.428 | +0.005 |
| ignored_non_shell_tool | 2.343 | 2.722 | 2.376 | +0.017 |
| allowed_simple_shell | 2.555 | 3.095 | 2.632 | +0.067 |
| allowed_typical_shell | 2.523 | 2.665 | 2.533 | +0.022 |
| allowed_workspace_script | 2.512 | 2.652 | 2.524 | +0.020 |
| denied_node_eval | 2.519 | 2.669 | 2.527 | +0.054 |
| denied_tmp_script_cleanup | 2.522 | 2.742 | 2.546 | +0.052 |
| allowed_patch_text_mentions_cleanup | 2.414 | 2.520 | 2.415 | -0.032 |
| denied_patch_delete_tmp_script | 2.448 | 2.878 | 2.507 | -0.004 |

Verdict: viable with a caveat. Median deltas are within noise (note `allowed_patch_text_mentions_cleanup` got *faster* than both prior runs, which shows the ±0.1 ms jitter floor of this benchmark). The caveat: these strings are part of the hook's observable contract — tests assert exact reason texts and agents parse the guidance — so changing them via config changes behavior, not just presentation. Keeping compile-time defaults identical to the old constants preserves compatibility.

## Attempt 3 - `needsDetailedShellScan` trigger table to config

What was moved: the ~110-line hand-written character switch that decides whether a command needs the full tokenizing scan. It was effectively a substring-trigger table over the lowercased command text (each case checked `strings.HasPrefix(text[index:], X)` at every index, which is equivalent to `strings.Contains(text, X)`).

How: new `scan_triggers` string array in `config/policy.json` (48 entries: pipes/heredocs/eval flags, interpreter and command names, `.codex` prefix, backtick, `$(`). The function became:

```go
func needsDetailedShellScan(commandText string) bool {
\tlowered := strings.ToLower(commandText)
\tfor _, trigger := range policy.scanTriggers {
\t\tif strings.Contains(lowered, trigger) {
\t\t\treturn true
\t\t}
\t}
\treturn false
}
```

This is also the first extraction where the config is *policy-relevant*: removing a trigger name from the array would skip the detailed scan for commands containing it, weakening enforcement. Same embedded-defaults + `ACG_POLICY_CONFIG` mechanism; triggers are validated only by tests, not at parse time.

Result after change (`go test .`: 169 passed):

Binary size: 1,771,538 bytes (-384 vs attempt 2; the deleted switch outweighs the added loop)

| case | median | p95 | mean | delta median vs attempt 2 |
| --- | --- | --- | --- | --- |
| baseline_spawn_true | 1.414 | 1.586 | 1.432 | +0.005 |
| ignored_non_shell_tool | 2.389 | 2.640 | 2.406 | +0.046 |
| allowed_simple_shell | 2.524 | 2.823 | 2.552 | -0.031 |
| allowed_typical_shell | 2.521 | 2.831 | 2.600 | -0.002 |
| allowed_workspace_script | 2.529 | 2.763 | 2.555 | +0.017 |
| denied_node_eval | 2.561 | 3.027 | 2.633 | +0.042 |
| denied_tmp_script_cleanup | 2.499 | 2.804 | 2.534 | -0.023 |
| allowed_patch_text_mentions_cleanup | 2.476 | 2.753 | 2.509 | +0.062 |
| denied_patch_delete_tmp_script | 2.474 | 2.780 | 2.509 | +0.026 |

Verdict: viable, with the weakest margin of the three. Medians drifted up ~0-40 µs on scan-heavy cases (`denied_node_eval`, `allowed_patch_text_mentions_cleanup`) because one pass over the text plus up to 48 `Contains` calls replaces the single-pass switch; most of that is inside noise but the direction is consistent. Functional checks passed: allow path stays silent, deny paths work with both a valid `ACG_POLICY_CONFIG` file and fallback to embedded defaults.

## Summary

| attempt | what moved to config | binary delta vs baseline | perf impact | verdict |
| --- | --- | --- | --- | --- |
| 1 | name sets (interpreters, wrappers, separators, keywords, tool names, remote commands) | +16,832 B (+0.96%) | none measurable | keep — pure data, no behavior change when edited |
| 2 | messages, markers, `scriptDir`, block reasons | +16,912 B (+0.96%) | none measurable | keep with caution — strings are an observable contract |
| 3 | detailed-scan trigger substrings | +16,528 B (+0.94%) | ≤ ~40 µs/call, borderline noise | acceptable — largest security sensitivity, guard it in review |

Overall conclusion: yes, configuration extraction is essentially free here. Process spawn (~1.4 ms) dominates everything; init-time parsing of <1 KB JSON with the hand-rolled scanner costs microseconds (quantified at ~6 µs in the follow-up below). All three extractions share one loader (`policy.go`), embed defaults via `go:embed`, and support runtime override through `ACG_POLICY_CONFIG`. The real cost is not performance but review discipline: attempts 2 and 3 turn code into behavior-bearing data, so config diffs need the same scrutiny as code diffs.

## Follow-up: isolating the config-load cost (µs resolution)

Objection addressed: every hook invocation is a fresh process, so the end-to-end benchmark includes ~1.4 ms of spawn per run and its jitter floor (~±50 µs) cannot resolve µs-level costs of the config load itself. The end-to-end numbers remain the correct *user-visible* metric (there is no cross-invocation caching to amortize anything into), but they under-report sensitivity. `policy_bench_test.go` adds micro-benchmarks that measure the load path directly (`go test -run '^$' -bench . -benchmem`, M3 Max):

| benchmark | ns/op | allocs | share of a 1.4 ms spawn |
| --- | --- | --- | --- |
| FullPolicyInit (parse + build sets, once per process) | 5,910–6,271 | 203 (10.2 KB) | ~0.4% |
| ParsePolicyJSON (hand-rolled parser) | 4,683–4,802 | 177 (5.9 KB) | ~0.3% |
| BuildPolicySets (map building) | 1,121–1,162 | 26 (4.3 KB) | <0.1% |
| SetLookupsHotPath (isPipeInterpreter+isWrapper+isRemoteCommand) | ~37.5 | 0 | negligible |
| PythonPrefixCheck | ~2.8 | 0 | negligible |

Scan-trigger comparison, original single-pass switch vs config-driven Contains loop over lowercased text:

| input | orig switch | config loop |
| --- | --- | --- |
| `echo hello && git status` | 42 ns | 135 ns |
| long pipe/cleanup chain (early hit) | 208 ns | 3.5 ns* |
| <code>rg ... \| head -20</code> (no trigger until end... early `-n` hit) | 110 ns | 3.8 ns* |
| `node -e ...` | 31 ns | 24 ns |

\* fast exits on the first matching trigger (`&&`, `|`). The only regression case is a command whose first trigger appears late; worst measured delta is ~93 ns — still three orders of magnitude below the end-to-end noise floor and invisible in the e2e table above.

Conclusion: total one-time config cost is ~6 µs/process (0.4% of spawn). The attempt-3 loop can be slower than the old switch only for late-first-trigger inputs, bounded at ~0.1 µs. Both are far below what the e2e harness can resolve, which retroactively validates treating its flat medians as "no measurable impact".

## Toolchain: latest Go and encoding/json/v2

- Installed: go1.27.0 darwin/arm64 = current latest stable (verified against go.dev/dl JSON). `go.mod` bumped `go 1.26` → `go 1.27`.
- `encoding/json/v2` compiles and runs unflagged on this toolchain (the GOEXPERIMENT=jsonv2 opt-in era ended; it now requires only the module `go` directive ≥ 1.27).
- Parser comparison on our actual `config/policy.json` (same struct shape, -benchmem, count 3):

| parser | ns/op | MB/s | allocs |
| --- | --- | --- | --- |
| hand-rolled parsePolicyInto | ~4,900 | ~386 | 177 (5.9 KB) |
| encoding/json/v2 Unmarshal | ~6,050 | ~314 | 77 (5.1 KB) |
| encoding/json v1 Unmarshal | ~7,430 | ~255 | 77 (5.1 KB) |

Verdict: json/v2 is ~20% faster than v1 as advertised, but the purpose-built scanner still wins (~20% faster than v2) because it skips fields we don't need without reflection and produces fewer intermediate allocations. Keeping the hand-rolled parser; json/v2 stays available as a drop-in if the config grows complex enough to make maintainability matter more than ~1 µs/init.

## Migration hardening: self-protection of `config/policy.json` (R1/R2)

Request: protect the new config file from the hook itself (otherwise R1/R2 — turning code into data — just shifts the attack surface).

Config: `protected_paths: ["config/policy.json"]` + `messages.protected_reason`. Default embedded, override via `ACG_POLICY_CONFIG` gets the same protection (the override path resolved at startup is also matched).

Enforcement: shell `rm/rmdir/unlink/trash(-put)` / `mv/cp/tee` / `find -delete` / `-exec rm` / redirections `> >| >> 2> &>` and patch `Delete File:` / `Update File:` touching a protected path return `protectedConfigReason`. To keep maintainability, the check is cwd-aware:

```go
cwdAllowsProtectedConfig(cwd) = strings.Contains(cwd, "agent-command-guard")
```

* `cwd` inside `agent-command-guard` (maintainer editing own policy) → allow
* any other `cwd` (agent in another project) → deny

This mirrors the existing `agent-quality-gate` gate (`cwdAllowsAgentQualityGate`). `needsDetailedShellScan` was also extended to always enter the detailed scan when the command contains a protected path (lower-cased), plus `scan_triggers` got `cp `, `mv `, `tee`, `policy.json`, `config/policy.json` so the scan is entered even before the destructive check.

Verification (hook invoked directly, `build/agent-command-guard` 1771858 B):

* `rm .codex/tmp-scripts/*` — still blocked for *any* `cwd` (inside/outside) ✓ — the original invariant is untouched
* `rm config/policy.json` with `cwd=/tmp/other` → deny `policy configuration` ✓
* `rm config/policy.json` with `cwd=/…/agent-command-guard` → allow ✓
* same split for `>`, `cp`, `tee`, `find -delete`, patch `Delete/Update` ✓
* `go vet` / `go test` 169 passed / `bun --cwd adapters/pi test` 8 passed ✓
* binary delta vs baseline 1,755,010 → 1,771,858 B (+16,848 B, +0.96%) — self-protection adds ~300 B over previous step

### External config as overlay (union + disable)

`ACG_POLICY_CONFIG` is now an overlay, not a full replacement. Empty = keep default, non-empty = patch:

* scalars `messages.*` — override if non-empty
* lists (`separators`, `wrappers`, `interpreters`, `protected_paths`, `scan_triggers`, …) — union add by default, disable via `-` prefix or clear via `[]`:

```json
{"protected_paths": ["custom.json"]}            // add custom.json, keep default
{"protected_paths": ["-config/policy.json"]}    // remove default
{"protected_paths": []}                           // clear all
{"scan_triggers": ["myTrigger", "-rm "]}       // add myTrigger, remove rm
```

Implementation: `parseStringArray` returns `[]string{}` (non-nil) for `[]` to distinguish missing key (`nil` → keep) vs explicit empty (`[]` → clear); `mergePolicyConfig` does `mergeStringSlice` with remove-then-add. Verified: `rm custom.json` blocked after union add, `rm config/policy.json` allowed after `-` or `[]`.
* same split for `>`, `cp`, `tee`, `find -delete`, patch `Delete/Update` ✓
* `go vet` / `go test` 169 passed / `bun --cwd adapters/pi test` 8 passed ✓
* binary delta vs baseline 1,755,010 → 1,771,554 B (+16,544 B, +0.94%) — the self-protection adds ~32 B over the previous step, noise-level in e2e medians (see benchmark above)
