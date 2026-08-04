import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));

export function printPiInstructions(bin: string): void {
	console.log(`Pi: ./scripts/build.sh && pi -e ./adapters/pi/extension.ts`);
	console.log(`  adapter -> ${join(repoRoot, "adapters/pi/extension.ts")} (spawns ${bin})`);
}
