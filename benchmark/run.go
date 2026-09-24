package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func run() error {
	hookCommand := flag.String("hook-command", defaultHookCommand(), "hook command to execute")
	hookLabel := flag.String("hook-label", "", "label to write into benchmark output")
	var selectedCases caseList
	flag.Var(&selectedCases, "case", "case to benchmark; repeatable; choices: "+strings.Join(sortedCaseNames(), ", "))
	flag.Parse()

	command, err := splitCommand(*hookCommand)
	if err != nil {
		return err
	}
	if len(command) == 0 {
		return fmt.Errorf("empty hook command")
	}
	if _, err := os.Stat(command[0]); err != nil {
		return fmt.Errorf("hook command not found: %s", command[0])
	}

	label := *hookLabel
	if label == "" {
		label = *hookCommand
	}

	results := []result{benchmarkBaseline(benchmarkIterations, benchmarkWarmup)}
	for _, caseName := range selectedCaseNames(selectedCases) {
		summary, err := benchmarkHook(command, caseName, benchmarkIterations, benchmarkWarmup)
		if err != nil {
			return err
		}
		results = append(results, summary)
	}

	printTable(results, label, benchmarkIterations, benchmarkWarmup)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
