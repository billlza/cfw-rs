// The stylesheet as the bundler reads it: styles.css imports its partials in
// cascade order and holds nothing else, so a test that checks a rule, or how
// later rules override earlier ones, reads the partials joined in that order.
import { readFile } from "node:fs/promises";

const IMPORT = /^@import "\.\/styles\/(?<name>[a-z0-9-]+\.css)";$/u;

/** The partials an entry imports, in order; anything else in it is refused. */
export function stylesheetImports(entry) {
  const names = [];
  for (const line of entry.replace(/\/\*.*?\*\//gsu, "").split("\n")) {
    const statement = line.trim();
    if (!statement) continue;
    const match = IMPORT.exec(statement);
    if (!match) throw new Error(`styles.css holds more than its imports: ${statement}`);
    names.push(match.groups.name);
  }
  if (names.length === 0) throw new Error("styles.css imports no partial");
  return names;
}

export async function readStylesheet() {
  const entry = await readFile(new URL("../../styles.css", import.meta.url), "utf8");
  const partials = await Promise.all(
    stylesheetImports(entry).map((name) => readFile(new URL(`../../styles/${name}`, import.meta.url), "utf8")),
  );
  return partials.join("\n");
}
