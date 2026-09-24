package main

import (
	"fmt"
	"strings"
)

func printTable(results []result, hookLabel string, iterations int, warmup int) {
	headers := []string{"case", "rc", "median", "p95", "mean", "min", "max", "out", "err"}
	rows := make([][]string, 0, len(results)+1)
	rows = append(rows, headers)

	for _, summary := range results {
		caseName, _ := summary["case"].(string)
		rows = append(rows, []string{
			caseName,
			formatReturnCodes(summary),
			formatMS(resultFloat(summary, "median_ms")),
			formatMS(resultFloat(summary, "p95_ms")),
			formatMS(resultFloat(summary, "mean_ms")),
			formatMS(resultFloat(summary, "min_ms")),
			formatMS(resultFloat(summary, "max_ms")),
			formatByteCount(summary, "first_stdout_bytes"),
			formatByteCount(summary, "first_stderr_bytes"),
		})
	}

	widths := make([]int, len(headers))
	for _, row := range rows {
		for index, cell := range row {
			if len(cell) > widths[index] {
				widths[index] = len(cell)
			}
		}
	}

	fmt.Printf("hook: %s\n", hookLabel)
	fmt.Printf("iterations: %d  warmup: %d\n\n", iterations, warmup)
	for rowIndex, row := range rows {
		for cellIndex, cell := range row {
			if cellIndex == 0 {
				fmt.Printf("%-*s", widths[cellIndex], cell)
			} else {
				fmt.Printf("  %*s", widths[cellIndex], cell)
			}
		}
		fmt.Println()
		if rowIndex == 0 {
			for cellIndex, width := range widths {
				if cellIndex > 0 {
					fmt.Print("  ")
				}
				fmt.Print(strings.Repeat("-", width))
			}
			fmt.Println()
		}
	}
}
