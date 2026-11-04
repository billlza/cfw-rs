// The stylesheet's entry: it imports every partial once, in cascade order, and
// nothing else, so the bundle holds every rule exactly once.
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

import { stylesheetImports } from "./support/stylesheet.mjs";

test("the stylesheet imports every partial once", async () => {
  const imports = stylesheetImports(await readFile(new URL("../styles.css", import.meta.url), "utf8"));
  const partials = await readdir(new URL("../styles/", import.meta.url));
  assert.equal(new Set(imports).size, imports.length, "no partial is imported twice");
  assert.deepEqual([...imports].sort(), [...partials].sort(), "every partial is imported");
});

test("the stylesheet's entry holds its partials' imports and nothing else", () => {
  assert.deepEqual(
    stylesheetImports('/* Order matters. */\n@import "./styles/base.css";\n\n@import "./styles/glass-menus.css";\n'),
    ["base.css", "glass-menus.css"],
  );
  assert.throws(
    () => stylesheetImports('@import "./styles/base.css";\n.cfw-title { color: red; }\n'),
    /holds more than its imports: \.cfw-title/u,
  );
  assert.throws(() => stylesheetImports('@import "../outside.css";\n'), /holds more than its imports/u);
  assert.throws(() => stylesheetImports('@import url("./styles/base.css");\n'), /holds more than its imports/u);
  assert.throws(() => stylesheetImports("/* No partial. */\n"), /imports no partial/u);
});
