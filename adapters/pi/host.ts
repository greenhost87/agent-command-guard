import { mkdir, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	DefaultResourceLoader,
	ExtensionRunner,
	ModelRegistry,
	ModelRuntime,
	SessionManager,
	SettingsManager,
	type ExtensionFactory,
} from "@earendil-works/pi-coding-agent";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
export const productionExtensionPath = join(repoRoot, "adapters/pi/extension.ts");

export type LoadedPiAdapter = {
	runner: ExtensionRunner;
	root: string;
};

export async function loadPiAdapter(
	factory?: ExtensionFactory,
	options?: { cwdPrefix?: string },
): Promise<LoadedPiAdapter> {
	process.env.PI_OFFLINE = "1";
	const root = await mkdtemp(join(tmpdir(), options?.cwdPrefix ?? "acg-pi-"));
	const agentDir = join(root, "agent");
	await mkdir(agentDir, { recursive: true });
	const settingsManager = SettingsManager.inMemory();
	const loader = new DefaultResourceLoader({
		cwd: root,
		agentDir,
		settingsManager,
		additionalExtensionPaths: factory ? [] : [productionExtensionPath],
		extensionFactories: factory ? [factory] : [],
		noSkills: true,
		noPromptTemplates: true,
		noThemes: true,
		noContextFiles: true,
	});
	await loader.reload();
	const loaded = loader.getExtensions();
	if (loaded.errors.length > 0) {
		throw new Error(loaded.errors.map((item) => `${item.path}: ${item.error}`).join("\n"));
	}
	if (loaded.extensions.length === 0) {
		throw new Error("Pi loader did not register the adapter");
	}

	const modelRuntime = await ModelRuntime.create({
		allowModelNetwork: false,
		modelsPath: null,
		authPath: join(root, "auth.json"),
		modelsStorePath: join(root, "models-store.json"),
	});
	const runner = new ExtensionRunner(
		loaded.extensions,
		loaded.runtime,
		root,
		SessionManager.inMemory(root),
		new ModelRegistry(modelRuntime),
	);
	return { runner, root };
}

export async function emitBash(runner: ExtensionRunner, command: string) {
	return runner.emitToolCall({
		type: "tool_call",
		toolCallId: "call-1",
		toolName: "bash",
		input: { command },
	});
}
