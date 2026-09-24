import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { spawn } from "node:child_process";
import type { ExtensionRunner } from "@earendil-works/pi-coding-agent";
import { createPiExtension } from "./extension.ts";
import { emitBash, loadPiAdapter, type LoadedPiAdapter } from "./host.ts";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const deniedCommand = `node -e "console.log(1)"`;

async function buildGuard(): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		const child = spawn(join(repoRoot, "scripts/build.sh"), [], {
			cwd: repoRoot,
			stdio: ["ignore", "pipe", "pipe"],
		});
		const stderr: Buffer[] = [];
		child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
		child.on("error", reject);
		child.on("close", (code) => {
			if (code === 0) {
				resolve();
				return;
			}
			reject(new Error(`build.sh exited ${code}: ${Buffer.concat(stderr).toString("utf8")}`));
		});
	});
}

describe("Pi adapter production path", () => {
	let runner: ExtensionRunner;
	let root: string;

	beforeAll(async () => {
		await buildGuard();
		({ runner, root } = await loadPiAdapter());
	});

	afterAll(async () => {
		if (root) {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("allows an accepted bash command without a block result", async () => {
		const result = await emitBash(runner, "true");
		expect(result).toBeUndefined();
	});

	it("blocks inline bash, saves its code, and forwards the file path", async () => {
		const result = await emitBash(runner, deniedCommand);
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain("Blocked inline interpreter code");
		expect(result?.reason).not.toContain("console.log(1)");
		const relative = result?.reason?.match(/\.codex\/tmp-scripts\/inline-[0-9a-f]{32}\.js/)?.[0];
		expect(relative).toBeDefined();
		const file = join(root, relative!);
		expect(await readFile(file, "utf8")).toBe("console.log(1)");
		expect((await stat(file)).mode & 0o777).toBe(0o600);
	});

	it("ignores non-bash tool calls", async () => {
		const result = await runner.emitToolCall({
			type: "tool_call",
			toolCallId: "call-2",
			toolName: "read",
			input: { path: "README.md" },
		});
		expect(result).toBeUndefined();
	});

	it("blocks ~/.agent-quality-gate access outside that project", async () => {
		const result = await emitBash(runner, "cat ~/.agent-quality-gate/config.json");
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain(
			"Blocked access to ~/.agent-quality-gate/ outside the agent-quality-gate project.",
		);
	});
});

describe("Pi adapter agent-quality-gate allow path", () => {
	let runner: ExtensionRunner;
	let root: string;

	beforeAll(async () => {
		await buildGuard();
		({ runner, root } = await loadPiAdapter(undefined, { cwdPrefix: "agent-quality-gate-" }));
	});

	afterAll(async () => {
		if (root) {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("allows ~/.agent-quality-gate access when cwd is that project", async () => {
		expect(root.includes("agent-quality-gate")).toBe(true);
		const result = await emitBash(runner, "cat ~/.agent-quality-gate/config.json");
		expect(result).toBeUndefined();
	});
});

describe("Pi adapter hook process failures", () => {
	const loaded: LoadedPiAdapter[] = [];

	afterAll(async () => {
		for (const item of loaded) {
			await rm(item.root, { recursive: true, force: true });
		}
	});

	async function loadWithHook(hookPath: string) {
		const item = await loadPiAdapter(createPiExtension(hookPath));
		loaded.push(item);
		return item.runner;
	}

	it("blocks when the shared binary cannot launch", async () => {
		const missing = join(await mkdtemp(join(tmpdir(), "acg-missing-")), "agent-command-guard");
		const runner = await loadWithHook(missing);
		const result = await emitBash(runner, "true");
		expect(result?.block).toBe(true);
		expect(result?.reason).toMatch(/^Protective hook failed:/);
	});

	it("blocks when the hook process exits unsuccessfully", async () => {
		const runner = await loadWithHook("/usr/bin/false");
		const result = await emitBash(runner, "true");
		expect(result).toEqual({
			block: true,
			reason: "Protective hook exited with code 1",
		});
	});

	it("blocks when the hook process returns invalid JSON", async () => {
		const runner = await loadWithHook("/usr/bin/uname");
		const result = await emitBash(runner, "true");
		expect(result).toEqual({
			block: true,
			reason: "Protective hook returned invalid JSON",
		});
	});
});
