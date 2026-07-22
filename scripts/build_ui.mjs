import { copyFile, mkdir, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "..");
const shellRoot = path.join(repositoryRoot, "apps", "cfw-tauri-shell");
const sourceRoot = path.join(shellRoot, "ui");
const outputRoot = path.join(sourceRoot, "dist");
const metadataRoot = path.join(repositoryRoot, "target", "ui-build");
const requireFromShell = createRequire(path.join(shellRoot, "package.json"));
const { build } = requireFromShell("esbuild");

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });
await mkdir(metadataRoot, { recursive: true });

await copyFile(path.join(sourceRoot, "index.html"), path.join(outputRoot, "index.html"));

const result = await build({
  absWorkingDir: repositoryRoot,
  bundle: true,
  charset: "utf8",
  entryPoints: {
    main: path.join(sourceRoot, "src", "main.js"),
    styles: path.join(sourceRoot, "styles.css"),
  },
  legalComments: "eof",
  logLevel: "warning",
  metafile: true,
  minify: true,
  outdir: outputRoot,
  platform: "browser",
  target: ["safari18"],
});

if (result.warnings.length !== 0) {
  throw new Error(`UI build emitted ${result.warnings.length} warning(s)`);
}

const metadata = {
  schemaVersion: 1,
  tool: {
    name: "esbuild",
    version: requireFromShell("esbuild/package.json").version,
  },
  metafile: result.metafile,
};
await writeFile(
  path.join(metadataRoot, "esbuild-meta.json"),
  `${JSON.stringify(canonicalize(metadata))}\n`,
  { encoding: "utf8", flag: "w", mode: 0o600 },
);
