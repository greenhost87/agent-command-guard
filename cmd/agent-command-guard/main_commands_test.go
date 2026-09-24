package main

import (
	"strings"
	"testing"
)

func TestDetectBlockReasonBlocksCaseInsensitiveCommandsThroughProxy(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{name: "upper rm through proxy", command: "rtk proxy RM -rf .codex/tmp-scripts", wantSubstr: "Blocked deletion of `.codex/tmp-scripts` audit scripts"},
		{name: "mixed case wrapper and rm", command: "RtK ProXY rM -rf .codex/tmp-scripts", wantSubstr: "Blocked deletion of `.codex/tmp-scripts` audit scripts"},
		{name: "pure uppercase rm", command: "RM -rf /tmp/example", wantSubstr: "Blocked deletion outside the workspace"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonBlocksDestructiveGitCommands(t *testing.T) {
	tests := []struct {
		command    string
		wantSubstr string
	}{
		{command: "git reset --hard", wantSubstr: "Blocked `git reset --hard`"},
		{command: "git reset HEAD --hard", wantSubstr: "Blocked `git reset --hard`"},
		{command: "git checkout -- README.md", wantSubstr: "Blocked `git checkout --`"},
		{command: "rtk git checkout -- .", wantSubstr: "Blocked `git checkout --`"},
		{command: "printf ok && git reset --hard HEAD", wantSubstr: "Blocked `git reset --hard`"},
		{command: "git reset --soft HEAD", wantSubstr: ""},
		{command: "git checkout feature", wantSubstr: ""},
		{command: "printf '%s\\n' 'git checkout -- README.md'", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

var pythonVersionAndEnvAssignmentTests = []struct {
	name       string
	command    string
	wantSubstr string
}{
	{
		name:       "python minor version inline eval",
		command:    "python3.11 -c 'print(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "python minor version through env assignment",
		command:    "env A=1 python3.11 -c 'print(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "pipe to python minor version after assignment",
		command:    "printf x | A=1 python3.11",
		wantSubstr: "Blocked pipe-to-interpreter (`| python3.11`)",
	},
	{
		name:       "non numeric python version is treated as python interpreter",
		command:    "python3.x -c 'print(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "perl combined eval flag",
		command:    "perl -we 'print 1'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "ruby combined eval flag",
		command:    "ruby -we 'puts 1'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "node stdin",
		command:    "node -",
		wantSubstr: "Blocked interpreter code from stdin/heredoc",
	},
	{
		name:       "git clean",
		command:    "git clean -fdx",
		wantSubstr: "Blocked `git clean`",
	},
	{
		name: "grouped rm home cache",
		command: strings.Join([]string{
			"log_file=/tmp/cleanup-colima-library.log",
			"{",
			"  rm -f ~/Library/Caches/Homebrew/api/formula/colima.json",
			"} > \"$log_file\" 2>&1",
		}, "\n"),
		wantSubstr: "Blocked deletion outside the workspace",
	},
	{
		name:       "relative rm is allowed",
		command:    "rm -f build/cache.json",
		wantSubstr: "",
	},
	{
		name:       "python combined inline flag",
		command:    "python3 -Ic 'print(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "bash combined inline flag",
		command:    "bash -lc 'echo hi'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "pipe to perl",
		command:    "printf 'print 1\\n' | perl",
		wantSubstr: "Blocked pipe-to-interpreter (`| perl`)",
	},
	{
		name:       "pipe to ruby",
		command:    "printf 'print 1\\n' | ruby",
		wantSubstr: "Blocked pipe-to-interpreter (`| ruby`)",
	},
	{
		name:       "pipe through env to python",
		command:    "printf 'print(1)\\n' | env python3",
		wantSubstr: "Blocked pipe-to-interpreter (`| python3`)",
	},
	{
		name:       "pipe through command wrapper to python",
		command:    "printf 'print(1)\\n' | command python3",
		wantSubstr: "Blocked pipe-to-interpreter (`| python3`)",
	},
	{
		name:       "env split string inline python",
		command:    "env -S 'python3 -c print(1)'",
		wantSubstr: "Blocked `env -S` split-string",
	},
	{
		name:       "shell eval",
		command:    "eval 'python3 -c \"print(1)\"'",
		wantSubstr: "Blocked shell `eval`",
	},
	{
		name:       "nodejs inline eval",
		command:    "nodejs -e 'console.log(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "pypy inline eval",
		command:    "pypy3 -c 'print(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "deno eval",
		command:    "deno eval 'console.log(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "bun inline eval",
		command:    "bun -e 'console.log(1)'",
		wantSubstr: "Blocked inline interpreter code",
	},
	{
		name:       "php stdin",
		command:    "php <<'PHP'\n<?php echo 1;\nPHP",
		wantSubstr: "Blocked interpreter code from stdin/heredoc",
	},
}

func TestDetectBlockReasonPythonVersionAndEnvAssignments(t *testing.T) {
	for _, tt := range pythonVersionAndEnvAssignmentTests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonBlocksSSHAndSCP(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{name: "ssh", command: "ssh example.com", wantSubstr: "Blocked `ssh`"},
		{name: "scp", command: "scp artifact.tar example.com:/tmp/", wantSubstr: "Blocked `scp`"},
		{name: "absolute path", command: "/usr/bin/ssh example.com", wantSubstr: "Blocked `ssh`"},
		{name: "rtk wrapper", command: "rtk scp artifact.tar example.com:/tmp/", wantSubstr: "Blocked `scp`"},
		{name: "env wrapper", command: "env SSH_AUTH_SOCK=/tmp/agent ssh example.com", wantSubstr: "Blocked `ssh`"},
		{name: "chained command", command: "printf ok && scp artifact.tar example.com:/tmp/", wantSubstr: "Blocked `scp`"},
		{name: "text argument", command: "printf '%s\\n' 'ssh example.com'", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}

func TestDetectBlockReasonBlocksInteractiveInterpreters(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		wantSubstr string
	}{
		{name: "bare python PTY entry", command: "rtk python3", wantSubstr: "Blocked interactive interpreter session"},
		{name: "bare python through env", command: "env A=1 python3", wantSubstr: "Blocked interactive interpreter session"},
		{name: "python interactive flag", command: "python3 -qi", wantSubstr: "Blocked interactive interpreter session"},
		{name: "bare shell PTY entry", command: "rtk bash", wantSubstr: "Blocked interactive interpreter session"},
		{name: "bare sh", command: "sh", wantSubstr: "Blocked interactive interpreter session"},
		{name: "sh interactive flag", command: "sh -i", wantSubstr: "Blocked interactive interpreter session"},
		{name: "node interactive flag", command: "node --interactive", wantSubstr: "Blocked interactive interpreter session"},
		{name: "php interactive flag", command: "php -a", wantSubstr: "Blocked interactive interpreter session"},
		{name: "deno repl", command: "deno repl", wantSubstr: "Blocked interactive interpreter session"},
		{name: "workspace python script", command: "python3 .codex/tmp-scripts/check.py", wantSubstr: ""},
		{name: "python version", command: "python3 --version", wantSubstr: ""},
		{name: "shell script", command: "bash .codex/tmp-scripts/check.sh", wantSubstr: ""},
		{name: "sh workspace script", command: "sh .codex/tmp-scripts/check.sh", wantSubstr: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBlockReason(tt.command)
			if tt.wantSubstr == "" {
				if got != "" {
					t.Fatalf("detectBlockReason(%q) = %q, want empty", tt.command, got)
				}
				return
			}
			if !strings.Contains(got, tt.wantSubstr) {
				t.Fatalf("detectBlockReason(%q) = %q, want substring %q", tt.command, got, tt.wantSubstr)
			}
		})
	}
}
