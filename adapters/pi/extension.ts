import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isBashToolResult, isToolCallEventType, type ExtensionAPI, type ExtensionFactory } from "@earendil-works/pi-coding-agent";

function resolveDefaultHookPath(): string {
	const envPath = process.env.ACG_BINARY ?? process.env.AGENT_COMMAND_GUARD_BIN;
	if (envPath && existsSync(envPath)) return envPath;

	const candidates = [
		fileURLToPath(new URL("../agent-command-guard", import.meta.url)),
		fileURLToPath(new URL("./agent-command-guard", import.meta.url)),
		fileURLToPath(new URL("../../build/agent-command-guard", import.meta.url)),
		join(homedir(), ".agent-command-guard/agent-command-guard"),
		join(homedir(), ".codex/hooks/agent-command-guard"),
		join(homedir(), ".cursor/hooks/agent-command-guard"),
	];
	for (const p of candidates) {
		if (existsSync(p)) return p;
	}
	return fileURLToPath(new URL("../../build/agent-command-guard", import.meta.url));
}

const defaultHookPath = resolveDefaultHookPath();

interface HookResponse {
	hookSpecificOutput?: {
		permissionDecision?: string;
		permissionDecisionReason?: string;
	};
	agentCommandGuard?: {
		rewriteCommand?: string;
		scriptPath?: string;
	};
}

interface InspectionResult {
	reason?: string;
	rewrite?: { command: string; scriptPath: string };
}

function inspectCommand(command: string, hookPath: string, cwd: string): Promise<InspectionResult> {
	return new Promise((resolve) => {
		const child = spawn(hookPath, [], {
			stdio: ["pipe", "pipe", "pipe"],
			env: { ...process.env, ACG_INTEGRATION: "pi" },
		});
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		let launchError: Error | undefined;

		child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
		child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
		child.stdin.on("error", () => {});
		child.on("error", (error: Error) => {
			launchError = error;
		});
		child.on("close", (code: number | null) => {
			if (launchError) {
				resolve({ reason: `Protective hook failed: ${launchError.message}` });
				return;
			}
			if (code !== 0) {
				const details = Buffer.concat(stderr).toString("utf8").trim();
				resolve({ reason: details ? `Protective hook exited with code ${code}: ${details}` : `Protective hook exited with code ${code}` });
				return;
			}

			const output = Buffer.concat(stdout).toString("utf8").trim();
			if (!output) {
				resolve({});
				return;
			}

			try {
				const response = JSON.parse(output) as HookResponse;
				const decision = response.hookSpecificOutput;
				if (decision?.permissionDecision === "deny") {
					resolve({ reason: decision.permissionDecisionReason ?? "Blocked by protective hook" });
					return;
				}
				const rewrite = response.agentCommandGuard;
				if (rewrite?.rewriteCommand && rewrite.scriptPath) {
					resolve({ rewrite: { command: rewrite.rewriteCommand, scriptPath: rewrite.scriptPath } });
					return;
				}
				resolve({ reason: "Protective hook returned an unexpected response" });
			} catch {
				resolve({ reason: "Protective hook returned invalid JSON" });
			}
		});

		child.stdin.end(JSON.stringify({
			tool_name: "Bash",
			tool_input: { command },
			cwd,
		}));
	});
}

export function createPiExtension(hookPath = defaultHookPath): ExtensionFactory {
	return (pi: ExtensionAPI) => {
		const stagedScripts = new Map<string, string>();

		pi.on("tool_call", async (event, ctx) => {
			if (!isToolCallEventType("bash", event)) return undefined;

			const result = await inspectCommand(event.input.command, hookPath, ctx.cwd);
			if (result.reason) return { block: true, reason: result.reason };
			if (result.rewrite) {
				event.input.command = result.rewrite.command;
				stagedScripts.set(event.toolCallId, result.rewrite.scriptPath);
			}
			return undefined;
		});

		pi.on("tool_result", (event) => {
			if (!isBashToolResult(event)) return undefined;
			const scriptPath = stagedScripts.get(event.toolCallId);
			if (!scriptPath) return undefined;
			stagedScripts.delete(event.toolCallId);
			return {
				content: [
					...event.content,
					{
						type: "text",
						text: `Guard saved and ran this script: ${scriptPath}. Continue working with this file (read or edit it directly); do not recreate the code inline.`,
					},
				],
			};
		});
	};
}

export default createPiExtension();
