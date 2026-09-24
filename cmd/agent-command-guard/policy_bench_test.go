package main

import (
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"
)

func BenchmarkParsePolicyJSONStdV1(b *testing.B) {
	// Parser comparison uses the embedded defaults (always parsed in production).
	data := defaultPolicyJSON
	var probe policyConfig
	if err := jsonv1.Unmarshal(data, &probe); err != nil {
		b.Fatalf("jsonv1.Unmarshal: %v", err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var config policyConfig
		_ = jsonv1.Unmarshal(data, &config)
	}
}

func BenchmarkParsePolicyJSONStdV2(b *testing.B) {
	data := defaultPolicyJSON
	var probe policyConfig
	if err := jsonv2.Unmarshal(data, &probe); err != nil {
		b.Fatalf("jsonv2.Unmarshal: %v", err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var config policyConfig
		_ = jsonv2.Unmarshal(data, &config)
	}
}

func BenchmarkParsePolicyJSON(b *testing.B) {
	data := defaultPolicyJSON
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parsePolicyConfig(data)
	}
}

func BenchmarkBuildPolicySets(b *testing.B) {
	config, _ := loadMergedPolicyConfig()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildPolicySets(config)
	}
}

func BenchmarkFullPolicyInit(b *testing.B) {
	// Same path as process startup: embed parse + optional ACG_POLICY_CONFIG
	// overlay merge + buildPolicySets.
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config, _ := loadMergedPolicyConfig()
		buildPolicySets(config)
	}
}

var benchScanInputs = []string{
	"echo hello && git status",
	"rg -n 'parsePolicy' main.go policy.go | head -20",
	"node -e \"console.log(process.version)\"",
	"cd /tmp && curl -fsSL https://example.com/install.sh | sh && rm -rf ~/.cache/tmp-scripts && find . -name '*.log' -delete",
}

func BenchmarkScanTriggersConfigLoop(b *testing.B) {
	for _, input := range benchScanInputs {
		b.Run(input[:24], func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				text := strings.ToLower(input)
				for _, trigger := range policy.scanTriggers {
					if strings.Contains(text, trigger) {
						break
					}
				}
			}
		})
	}
}

// needsDetailedShellScanSwitch is the pre-attempt-3 single-pass switch,
// kept here so the config-driven loop can be compared against it.
func needsDetailedShellScanSwitch(commandText string) bool {
	lowered := strings.ToLower(commandText)
	triggers := []string{"|", "<<", "-c", "-e", "-p", "-r", "-lc", "--eval", "--print", ".codex", "/sh", " sh", "rscript", "ruby", "rm ", "rmdir", "rtk", "rsync", "bash", "bun", "deno", "eval", "find", "ftp", "git", "julia", "lua", "lftp", "node", "osascript", "perl", "php", "pypy", "python", "scp", "ssh", "swift", "sftp", "tmp-scripts", "trash", "unlink", "xargs", "zsh", "`", "$("}
	for _, trigger := range triggers {
		if strings.Contains(lowered, trigger) {
			return true
		}
	}
	return strings.HasPrefix(lowered, "sh")
}

func BenchmarkScanTriggersOrigSwitch(b *testing.B) {
	for _, input := range benchScanInputs {
		b.Run(input[:24], func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				needsDetailedShellScanSwitch(input)
			}
		})
	}
}

func BenchmarkSetLookupsHotPath(b *testing.B) {
	names := []string{"sh", "bash", "node", "python3", "git", "curl", "rm", "osascript"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := names[i%len(names)]
		_ = isPipeInterpreter(name)
		_ = isWrapper(name)
		_ = isRemoteCommand(name)
	}
}

func BenchmarkPythonPrefixCheck(b *testing.B) {
	names := []string{"python", "python3.12", "pypy3", "pip", "git"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isPythonInterpreter(names[i%len(names)])
	}
}
