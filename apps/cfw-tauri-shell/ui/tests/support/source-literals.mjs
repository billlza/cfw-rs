// Finds the text a dashboard source file carries as string literals, and says
// where each one stands: inside a t() message, inside an Error, in a table at
// module level, or in running code. The catalog test uses it to refuse
// interface text that never reaches a translation.
//
// This is a tokenizer, not a parser. It refuses input it cannot follow instead
// of guessing, so a construct it does not know fails the test that uses it.

const PUNCTUATORS = [
  ">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
  "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=",
  "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
];
// After these words a slash starts a regular expression, not a division.
const REGEX_AFTER_WORD = new Set([
  "return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do", "instanceof", "yield", "await",
]);
// A brace after one of these opens a block of statements, not an object.
const BLOCK_AFTER_WORD = new Set(["else", "try", "finally", "do"]);
const SIMPLE_ESCAPES = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", 0: "\0" };
const IDENTIFIER_START = /[\p{ID_Start}$_]/u;
const IDENTIFIER_PART = /[\p{ID_Continue}$\u200c\u200d]/u;

class SourceError extends Error {}

function fail(file, line, message) {
  throw new SourceError(`${file}:${line}: ${message}`);
}

/// Splits one module into tokens. A template literal is one token that holds
/// its static chunks and the tokens of each interpolation.
export function tokenize(source, file = "<source>") {
  let index = 0;
  let line = 1;

  function escape() {
    // `index` is on the character after the backslash.
    const character = source[index];
    index += 1;
    if (character === "\n") { line += 1; return ""; }
    if (character === "x") {
      const digits = source.slice(index, index + 2);
      if (!/^[0-9A-Fa-f]{2}$/u.test(digits)) fail(file, line, "invalid \\x escape");
      index += 2;
      return String.fromCodePoint(Number.parseInt(digits, 16));
    }
    if (character === "u") {
      const braced = source[index] === "{";
      const end = braced ? source.indexOf("}", index) : index + 4;
      const digits = braced ? source.slice(index + 1, end) : source.slice(index, end);
      if (end < 0 || !/^[0-9A-Fa-f]{1,6}$/u.test(digits)) fail(file, line, "invalid \\u escape");
      index = braced ? end + 1 : end;
      return String.fromCodePoint(Number.parseInt(digits, 16));
    }
    return Object.hasOwn(SIMPLE_ESCAPES, character) ? SIMPLE_ESCAPES[character] : character;
  }

  function quoted(quote) {
    const startLine = line;
    index += 1;
    let value = "";
    for (;;) {
      if (index >= source.length || source[index] === "\n") fail(file, startLine, "unterminated string");
      const character = source[index];
      index += 1;
      if (character === quote) return { type: "string", value, line: startLine };
      value += character === "\\" ? escape() : character;
    }
  }

  function template() {
    const startLine = line;
    index += 1;
    const chunks = [""];
    const interpolations = [];
    for (;;) {
      if (index >= source.length) fail(file, startLine, "unterminated template literal");
      const character = source[index];
      index += 1;
      if (character === "`") return { type: "template", chunks, interpolations, line: startLine };
      if (character === "$" && source[index] === "{") {
        index += 1;
        interpolations.push(tokens("}"));
        chunks.push("");
      } else if (character === "\\") {
        chunks[chunks.length - 1] += escape();
      } else {
        if (character === "\n") line += 1;
        chunks[chunks.length - 1] += character;
      }
    }
  }

  function regularExpression() {
    const startLine = line;
    index += 1;
    let inClass = false;
    for (;;) {
      if (index >= source.length || source[index] === "\n") fail(file, startLine, "unterminated regular expression");
      const character = source[index];
      index += 1;
      if (character === "\\") index += 1;
      else if (character === "[") inClass = true;
      else if (character === "]") inClass = false;
      else if (character === "/" && !inClass) break;
    }
    while (index < source.length && IDENTIFIER_PART.test(source[index])) index += 1;
    return { type: "regex", line: startLine };
  }

  function slashStartsRegex(previous) {
    if (!previous) return true;
    if (previous.type === "word") return REGEX_AFTER_WORD.has(previous.value);
    if (previous.type === "punctuator") return ![")", "]", "}"].includes(previous.value);
    return false;
  }

  /// Tokens up to the end of input, or up to the brace that closes an
  /// interpolation when `closer` is "}".
  function tokens(closer = null) {
    const list = [];
    let braces = 0;
    for (;;) {
      if (index >= source.length) {
        if (closer) fail(file, line, "unterminated template interpolation");
        return list;
      }
      const character = source[index];
      if (character === "\n") { line += 1; index += 1; continue; }
      if (/\s/u.test(character)) { index += 1; continue; }
      if (character === "/" && source[index + 1] === "/") {
        const end = source.indexOf("\n", index);
        index = end < 0 ? source.length : end;
        continue;
      }
      if (character === "/" && source[index + 1] === "*") {
        const end = source.indexOf("*/", index + 2);
        if (end < 0) fail(file, line, "unterminated comment");
        line += source.slice(index, end).split("\n").length - 1;
        index = end + 2;
        continue;
      }
      if (character === '"' || character === "'") { list.push(quoted(character)); continue; }
      if (character === "`") { list.push(template()); continue; }
      if (character === "/" && slashStartsRegex(list.at(-1))) { list.push(regularExpression()); continue; }
      if (IDENTIFIER_START.test(character)) {
        const start = index;
        while (index < source.length && IDENTIFIER_PART.test(source[index])) index += 1;
        list.push({ type: "word", value: source.slice(start, index), line });
        continue;
      }
      if (/[0-9]/u.test(character) || (character === "." && /[0-9]/u.test(source[index + 1] ?? ""))) {
        const start = index;
        while (index < source.length && /[0-9A-Za-z_.]/u.test(source[index])) index += 1;
        list.push({ type: "number", value: source.slice(start, index), line });
        continue;
      }
      if (closer && character === "}" && braces === 0) { index += 1; return list; }
      if (character === "{") braces += 1;
      if (character === "}") braces -= 1;
      const punctuator = PUNCTUATORS.find((candidate) => source.startsWith(candidate, index)) ?? character;
      if (!/^[-+*/%=<>!&|^~?:;,.()[\]{}#@]/u.test(punctuator)) fail(file, line, `unexpected character ${JSON.stringify(character)}`);
      index += punctuator.length;
      list.push({ type: "punctuator", value: punctuator, line });
    }
  }

  return tokens();
}

const MARKUP = /<[A-Za-z!/]/u;

/// The text nodes and the readable attribute values of a literal that holds
/// markup. Interpolations are opaque.
function markupText(chunks) {
  const HOLE = "\u0001";
  const text = chunks.join(HOLE);
  const found = [];
  for (const tag of text.matchAll(/<[^<>]*>/gu)) {
    for (const attribute of tag[0].matchAll(/\b(?:title|aria-label|placeholder|alt)="([^"\u0001]*)"/gu)) found.push(attribute[1]);
  }
  for (const node of text.replace(/<[^<>]*>/gu, HOLE).split(HOLE)) found.push(node);
  return found;
}

/// Every literal text of one module with its standing:
///   translated  it is, or is one choice of, the message argument of t()
///   diagnostic  it is an argument of `new …Error(…)`
///   table       it stands at module level outside any function or call
///   code        anything else: text a running function produces
export function sourceLiterals(source, file = "<source>") {
  const found = [];

  function walk(tokens, inherited) {
    // Each frame is one open bracket. `arrow` marks an arrow function whose
    // body is an expression in that frame.
    const frames = [{ ...inherited, arrow: false }];
    const top = () => frames.at(-1);
    const standing = () => {
      // The message of the nearest t() call, unless another call inside that
      // argument takes the literal for itself.
      const call = frames.findLastIndex((entry) => entry.translated);
      if (call >= 0 && frames[call].argument === 0 && !frames.slice(call + 1).some((entry) => entry.bracket === "(")) return "translated";
      if (frames.some((entry) => entry.diagnostic)) return "diagnostic";
      return frames.some((entry) => entry.code || entry.arrow) ? "code" : "table";
    };
    const comparison = (token) => token?.type === "punctuator" && ["===", "!==", "==", "!="].includes(token.value);
    tokens.forEach((token, position) => {
      const previous = tokens[position - 1];
      const beforePrevious = tokens[position - 2];
      if (token.type === "string" || token.type === "template") {
        const chunks = token.type === "string" ? [token.value] : token.chunks;
        const composed = token.type === "template" && token.interpolations.length > 0;
        const markup = chunks.some((chunk) => MARKUP.test(chunk));
        // Only a whole plain literal can be the message of t(). Markup and
        // the fixed parts of a composed text are what a function writes out.
        const where = standing();
        const literalStanding = where === "translated" && (markup || composed) ? "code" : where;
        // A literal a condition compares with is a value, not a text.
        const compared = comparison(previous) || comparison(tokens[position + 1]);
        for (const text of markup ? markupText(chunks) : chunks) {
          found.push({ text, line: token.line, standing: literalStanding, markup, composed, compared });
        }
        if (token.type === "template") {
          const inner = { code: true, translated: false, diagnostic: where === "diagnostic", argument: 0 };
          for (const interpolation of token.interpolations) walk(interpolation, inner);
        }
        return;
      }
      if (token.type !== "punctuator") return;
      if (token.value === "=>") { top().arrow = true; return; }
      if (token.value === ";") { top().arrow = false; return; }
      if (token.value === ",") {
        const frame = top();
        if (frame.bracket === "(") frame.argument += 1;
        if (frame.bracket !== undefined) frame.arrow = false;
        return;
      }
      if (token.value === "(") {
        const member = beforePrevious?.type === "punctuator" && [".", "?."].includes(beforePrevious.value);
        const callee = previous?.type === "word" ? previous.value : null;
        const translated = callee === "t" && !member;
        const diagnostic = callee !== null && /Error$/u.test(callee) && beforePrevious?.type === "word" && beforePrevious.value === "new";
        // Freezing a table does not turn it into code.
        const freeze = callee === "freeze" && member;
        frames.push({ bracket: "(", translated, diagnostic, argument: 0, code: !freeze && !translated && !diagnostic, arrow: false });
        return;
      }
      if (token.value === "[") {
        frames.push({ bracket: "[", translated: false, diagnostic: false, argument: 0, code: false, arrow: false });
        return;
      }
      if (token.value === "{") {
        const block = previous !== undefined && (
          (previous.type === "punctuator" && [")", "=>"].includes(previous.value))
          || (previous.type === "word" && BLOCK_AFTER_WORD.has(previous.value))
        );
        frames.push({ bracket: "{", translated: false, diagnostic: false, argument: 0, code: block, arrow: false });
        return;
      }
      if ([")", "]", "}"].includes(token.value)) {
        const expected = { ")": "(", "]": "[", "}": "{" }[token.value];
        if (frames.length < 2 || top().bracket !== expected) fail(file, token.line, `unbalanced ${token.value}`);
        frames.pop();
      }
    });
    if (frames.length !== 1) fail(file, tokens.at(-1)?.line ?? 1, "unclosed bracket");
  }

  walk(tokenize(source, file), { code: false, translated: false, diagnostic: false, argument: 0 });
  return found;
}

// Kana, CJK ideographs and their compatibility forms, half-width kana.
const CJK = /[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff66-\uff9f]/u;

/// Whether a literal reads as a sentence or a label rather than an
/// identifier, a class list or a format. Single lower-case words cannot be
/// told from identifiers and are out of reach.
export function looksLikeProse(text, { markup = false, composed = false } = {}) {
  const value = text.trim();
  if (CJK.test(value)) return true;
  if (/[A-Za-z]/u.test(value) && /(?:…|\.\.\.)$/u.test(value)) return true;
  // Attribute fragments and selectors.
  if (/=["']|^[.#[]/u.test(value)) return false;
  // Between tags even one word is shown as it stands. Abbreviations and
  // units ("URL", "ms") have no lower-case run of three letters.
  if (markup) return /[A-Za-z][a-z]{2,}/u.test(value);
  // Words stand apart: "ipv6DNS" and "kind,requestId" are one token each.
  const words = value.split(/\s+/u).filter((token) => /^\p{P}*[A-Za-z][A-Za-z'’-]*\p{P}*$/u.test(token));
  if (words.length < 2 || !words.some((word) => /[A-Za-z][a-z]{2,}/u.test(word))) return false;
  // The fixed part of a composed sentence is prose even in lower case; a
  // plain literal needs a capital to be told from a class list or a key.
  return composed || /[A-Z]/u.test(value);
}
