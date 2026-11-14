// Interface text must reach a translation. A literal that reads as a sentence
// or a label is either the message of t(), a table entry the catalogs know, an
// Error message, or one of the few literals listed here with its reason.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import { catalogs } from "../src/i18n.js";
import { looksLikeProse, sourceLiterals, tokenize } from "./support/source-literals.mjs";

// Literals no reader takes for interface text, by source file.
const NOT_INTERFACE_TEXT = Object.freeze({
  // Protocol names.
  "connection-diagnostics.js": ["WebRTC / UDP"],
  // Typeface names and CSS font stacks.
  "font-preferences.js": [
    "Avenir Next", "SF Mono", "Segoe UI",
    '"Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif',
    '"SF Mono", Menlo, Consolas, monospace',
    '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif',
    '"Segoe UI", system-ui, sans-serif',
    "Consolas, ui-monospace, monospace",
  ],
  // The product's slogan, part of its mark.
  "general.js": ["Less Network", "More Freedom"],
  // Each language is named in itself.
  "i18n.js": ["简体中文", "繁體中文", "日本語"],
  // The native menu's protocol violation, reported like an Error message.
  "native-profile-menu.js": ["Native profile menu returned an invalid result"],
  // The shape of an address, not words.
  "profile-dialogs.js": ["https://..."],
  // The name of the release feed.
  "settings-view.js": ["GitHub Releases"],
  // A placeholder record; no page shows its name.
  "state.js": ["No Profile"],
});

function analyse(source) {
  return sourceLiterals(source, "sample.js")
    .filter((literal) => looksLikeProse(literal.text, literal))
    .map(({ text, standing }) => [text.trim(), standing]);
}

test("the scanner tells a message, a table entry, a diagnostic and running text apart", () => {
  assert.deepEqual(analyse(`
    const TABLE = Object.freeze({ first: "First label", second: ["Second label"] });
    export function render(busy) {
      const reason = busy ? "Raw reason here" : t("Translated reason");
      if (!busy) throw new TypeError("Diagnostic reason here");
      return reason;
    }
  `), [
    ["First label", "table"], ["Second label", "table"],
    ["Raw reason here", "code"], ["Translated reason", "translated"],
    ["Diagnostic reason here", "diagnostic"],
  ]);
});

test("only the message argument of t() is a message", () => {
  assert.deepEqual(analyse(`
    const one = (flag) => t(flag ? "Chosen message one" : "Chosen message two", { name: "Raw Parameter text" });
    const two = () => t({ a: "Looked up message" }[kind] ?? "Fallback message");
    const three = () => host.t("Another object's method");
    const four = () => new RangeError(t("Translated diagnostic text"));
    const five = () => t(describe("Nested call text"), { name });
  `), [
    ["Chosen message one", "translated"], ["Chosen message two", "translated"], ["Raw Parameter text", "code"],
    ["Looked up message", "translated"], ["Fallback message", "translated"],
    ["Another object's method", "code"],
    ["Translated diagnostic text", "translated"],
    ["Nested call text", "code"],
  ]);
});

test("an arrow function's expression is running text even at module level", () => {
  assert.deepEqual(analyse(`
    const label = (busy) => busy ? "Busy label text" : "Idle label text";
    const TABLE = { render: (value) => "Rendered label text", plain: "Plain table text" };
    const after = "Later table text";
  `), [
    ["Busy label text", "code"], ["Idle label text", "code"],
    ["Rendered label text", "code"], ["Plain table text", "table"],
    ["Later table text", "table"],
  ]);
});

test("markup yields its text nodes and readable attributes, never its tags", () => {
  assert.deepEqual(analyse(`
    function render(model) {
      return \`<section class="panel wide" title="Panel tooltip text" data-kind="\${model.kind}">
        <h3>Heading text here</h3>
        <button class="button \${model.busy ? "busy now" : ""}" \${model.busy ? "disabled" : ""}>\${model.busy ? "Working…" : t("Start work")}</button>
        <p>版本 \${model.version}</p>
        <dl><dt>helper</dt><dd>URL</dd></dl>
        <small>\${escapeHtml(t("Translated note text"))}</small>
      </section>\`;
    }
  `), [
    ["Panel tooltip text", "code"], ["Heading text here", "code"], ["版本", "code"], ["helper", "code"],
    ["Working…", "code"], ["Start work", "translated"], ["Translated note text", "translated"],
  ]);
});

test("the fixed part of a composed text counts even in lower case", () => {
  assert.deepEqual(analyse(`
    function describe(label, rate) {
      const first = \`\${label} is required\`;
      const second = \`\${rate}/s\`;
      const third = \`data-group="\${label}" data-node="\${rate}"\`;
      return new TypeError(\`\${label} must be enabled or disabled\`);
    }
  `), [["is required", "code"], ["must be enabled or disabled", "diagnostic"]]);
});

test("identifiers, class lists and formats are not prose", () => {
  for (const text of [
    "cfw-status-dot on", "button ghost", "ipv6DNS", "kind,requestId", "info", "Off", "TUN MTU", "0 B/s",
    'width="18" height="18"', "[data-action]", ".panel .row", "#page", "sing-box", "",
  ]) assert.equal(looksLikeProse(text), false, text);
  for (const text of ["Switch proxy mode", "Checking…", "Updating...", "macOS requires approval", "版本", "日本語", "Tick the box."]) {
    assert.equal(looksLikeProse(text), true, text);
  }
  assert.equal(looksLikeProse("is required", { composed: true }), true);
  assert.equal(looksLikeProse("or later", { markup: true }), true);
  assert.equal(looksLikeProse("helper", { markup: true }), true);
  assert.equal(looksLikeProse("helper"), false);
  for (const text of ["URL", "UDP", "ms", "TUN MTU", "IPv6 DNS", "×"]) assert.equal(looksLikeProse(text, { markup: true }), false, text);
  assert.equal(looksLikeProse("is required"), false);
});

test("the scanner follows comments, regular expressions and nested templates, and refuses what it cannot", () => {
  assert.deepEqual(analyse(`
    // "Commented text here" is not a literal
    /* 'Nor this text here' */
    const pattern = /["'\`]Quoted in a pattern[\\]/]/u;
    const ratio = total / count / 2;
    function render(rows) {
      return \`<ul>\${rows.map((row) => \`<li title="\${row.note}">\${row.done ? "Done already" : \`\${row.name} is pending\`}</li>\`).join("")}</ul>\`;
    }
  `), [["Done already", "code"], ["is pending", "code"]]);
  assert.equal(tokenize("const value = 'it\\'s';")[3].value, "it's");
  assert.equal(tokenize('const value = "\\u00e9\\x41\\n";')[3].value, "éA\n");
  assert.throws(() => tokenize('const open = "never closed;\n', "bad.js"), /bad\.js:1: unterminated string/u);
  assert.throws(() => tokenize("const open = `never closed;", "bad.js"), /bad\.js:1: unterminated template literal/u);
  assert.throws(() => sourceLiterals("function f() { return (1; }", "bad.js"), /bad\.js:1: unbalanced \}/u);
  assert.throws(() => sourceLiterals("const list = [1, 2;", "bad.js"), /bad\.js:1: unclosed bracket/u);
});

/// What `sources` carry that reaches no translation: prose outside t(), a
/// message t() chooses that `catalog` lacks, and entries of `listed` that no
/// source carries any more.
function findings(sources, catalog, listed) {
  const unused = new Set(Object.entries(listed).flatMap(([file, texts]) => texts.map((text) => `${file}: ${text}`)));
  const untranslated = [];
  const unknown = [];
  for (const [file, source] of sources) {
    const accepted = listed[file] ?? [];
    for (const literal of sourceLiterals(source, file)) {
      if (literal.standing === "translated") {
        // Also a message that t() chooses with a condition or looks up. An
        // empty literal is the absence of a text.
        const message = literal.text !== "" && !literal.compared;
        if (message && !Object.hasOwn(catalog, literal.text)) unknown.push(`${file}:${literal.line}: ${JSON.stringify(literal.text)}`);
        continue;
      }
      if (literal.standing === "diagnostic" || !looksLikeProse(literal.text, literal)) continue;
      if (literal.standing === "table" && Object.hasOwn(catalog, literal.text)) continue;
      const text = literal.text.trim();
      if (accepted.includes(text)) { unused.delete(`${file}: ${text}`); continue; }
      untranslated.push(`${file}:${literal.line}: ${JSON.stringify(text)}`);
    }
  }
  const files = new Set(sources.map(([file]) => file));
  return { untranslated, unknown, unused: [...unused], unlisted: Object.keys(listed).filter((file) => !files.has(file)) };
}

test("the guard reports raw prose, a chosen message the catalog lacks and a stale exception", () => {
  const sources = [
    ["view.js", `
      const LABELS = { known: "Known table label", raw: "Unknown table label" };
      export function render(busy, kind) {
        const title = busy ? "Raw busy title" : t("Known title text");
        const note = t(busy ? "Chosen but missing" : "Known title text");
        const name = "Accepted brand name";
        if (!kind) throw new RangeError("Diagnostic text here");
        return t(kind === "Compared kind value" ? "Known title text" : "") + title + note + name;
      }
    `],
    ["other.js", 'export const label = () => t("Known title text");'],
  ];
  const catalog = { "Known table label": "", "Known title text": "" };
  const listed = { "view.js": ["Accepted brand name", "Gone from the source"], "gone.js": ["Anything at all"] };
  assert.deepEqual(findings(sources, catalog, listed), {
    untranslated: ['view.js:2: "Unknown table label"', 'view.js:4: "Raw busy title"'],
    unknown: ['view.js:5: "Chosen but missing"'],
    unused: ["view.js: Gone from the source", "gone.js: Anything at all"],
    unlisted: ["gone.js"],
  });
  assert.deepEqual(findings(sources.slice(1), catalog, {}), { untranslated: [], unknown: [], unused: [], unlisted: [] });
});

test("every sentence and label in the dashboard sources reaches a translation", () => {
  const root = new URL("../src/", import.meta.url);
  const sources = readdirSync(root).filter((name) => name.endsWith(".js")).sort()
    .map((file) => [file, readFileSync(new URL(file, root), "utf8")]);
  assert.ok(sources.length > 50, "the dashboard sources were found");
  const found = findings(sources, catalogs.en, NOT_INTERFACE_TEXT);
  assert.deepEqual(found.untranslated, [], "wrap the text in t() and add it to the four catalogs");
  assert.deepEqual(found.unknown, [], "messages of t() that the catalogs do not hold");
  assert.deepEqual(found.unused, [], "listed literals that no source file carries any more");
  assert.deepEqual(found.unlisted, [], "listed files that are gone");
});
