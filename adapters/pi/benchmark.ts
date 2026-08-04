import { rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { emitBash, loadPiAdapter } from "./host.ts";

const iterations = 300;
const warmup = 20;
const hookPath = join(fileURLToPath(new URL("../..", import.meta.url)), "build/agent-command-guard");

const cases = [
	{ name: "allowed_simple_shell", command: "true", expectBlock: false },
	{ name: "allowed_typical_shell", command: "sed -n '1,120p' /tmp/example.txt", expectBlock: false },
	{ name: "denied_node_eval", command: `node -e "console.log(1)"`, expectBlock: true },
] as const;

type Stats = {
	min: number;
	median: number;
	mean: number;
	p95: number;
	max: number;
};

function percentile(sorted: number[], value: number): number {
	if (sorted.length === 1) {
		return sorted[0];
	}
	const position = (sorted.length - 1) * value;
	const lower = Math.floor(position);
	const upper = Math.min(lower + 1, sorted.length - 1);
	const fraction = position - lower;
	return sorted[lower] * (1 - fraction) + sorted[upper] * fraction;
}

function summarize(values: number[]): Stats {
	const sorted = [...values].sort((a, b) => a - b);
	const total = sorted.reduce((sum, value) => sum + value, 0);
	const median = sorted.length % 2 === 0
		? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2
		: sorted[Math.floor(sorted.length / 2)];
	return {
		min: sorted[0],
		median,
		mean: total / sorted.length,
		p95: percentile(sorted, 0.95),
		max: sorted[sorted.length - 1],
	};
}

function formatMS(value: number): string {
	return value.toFixed(3);
}

function stdinFor(command: string): string {
	return JSON.stringify({
		tool_name: "Bash",
		tool_input: { command },
	});
}

async function runGoDirect(command: string): Promise<{ elapsed: number; blocked: boolean }> {
	const started = performance.now();
	const { blocked } = await new Promise<{ blocked: boolean }>((resolve, reject) => {
		const child = spawn(hookPath, [], { stdio: ["pipe", "pipe", "pipe"] });
		const stdout: Buffer[] = [];
		child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
		child.stderr.on("data", () => {});
		child.on("error", reject);
		child.on("close", (code) => {
			if (code !== 0) {
				reject(new Error(`go_direct exited ${code}`));
				return;
			}
			const output = Buffer.concat(stdout).toString("utf8").trim();
			if (!output) {
				resolve({ blocked: false });
				return;
			}
			try {
				const response = JSON.parse(output) as {
					hookSpecificOutput?: { permissionDecision?: string };
				};
				resolve({ blocked: response.hookSpecificOutput?.permissionDecision === "deny" });
			} catch (error) {
				reject(error);
			}
		});
		child.stdin.end(stdinFor(command));
	});
	return { elapsed: performance.now() - started, blocked };
}

async function measurePaired(
	goRun: () => Promise<number>,
	piRun: () => Promise<number>,
): Promise<{ go: number[]; pi: number[]; ts: number[] }> {
	for (let index = 0; index < warmup; index++) {
		await goRun();
		await piRun();
	}
	const go: number[] = [];
	const pi: number[] = [];
	const ts: number[] = [];
	for (let index = 0; index < iterations; index++) {
		const goElapsed = await goRun();
		const piElapsed = await piRun();
		go.push(goElapsed);
		pi.push(piElapsed);
		ts.push(piElapsed - goElapsed);
	}
	return { go, pi, ts };
}

function printTable(headers: string[], rows: string[][]) {
	const table = [headers, ...rows];
	const widths = headers.map((_, column) => Math.max(...table.map((row) => row[column].length)));
	for (const row of table) {
		console.log(row.map((cell, column) => cell.padEnd(widths[column])).join("  "));
	}
}

function statsRow(name: string, stats: Stats): string[] {
	return [name, formatMS(stats.median), formatMS(stats.p95), formatMS(stats.mean), formatMS(stats.min), formatMS(stats.max)];
}

const { runner, root } = await loadPiAdapter();
try {
	console.log(`Pi TS wrapper overhead (ms); iterations=${iterations} warmup=${warmup}`);
	console.log("go_direct = spawn(build/agent-command-guard) + same Bash stdin JSON");
	console.log("pi_full   = Pi emitToolCall through adapters/pi/extension.ts (includes go_direct work)");
	console.log("ts_wrap   = paired (pi_full - go_direct) per iteration — adapter overhead above Go");
	console.log("Local only. No model, no ~/.pi auth.");
	console.log("");

	const rows: string[][] = [];
	for (const item of cases) {
		const paired = await measurePaired(
			async () => {
				const result = await runGoDirect(item.command);
				if (result.blocked !== item.expectBlock) {
					throw new Error(`${item.name} go_direct: expected block=${item.expectBlock}`);
				}
				return result.elapsed;
			},
			async () => {
				const started = performance.now();
				const result = await emitBash(runner, item.command);
				const blocked = result?.block === true;
				if (blocked !== item.expectBlock) {
					throw new Error(`${item.name} pi_full: expected block=${item.expectBlock}, got ${JSON.stringify(result)}`);
				}
				return performance.now() - started;
			},
		);
		rows.push(statsRow(`${item.name}/go_direct`, summarize(paired.go)));
		rows.push(statsRow(`${item.name}/pi_full`, summarize(paired.pi)));
		rows.push(statsRow(`${item.name}/ts_wrap`, summarize(paired.ts)));
	}

	printTable(["case", "median", "p95", "mean", "min", "max"], rows);
} finally {
	await rm(root, { recursive: true, force: true });
}
