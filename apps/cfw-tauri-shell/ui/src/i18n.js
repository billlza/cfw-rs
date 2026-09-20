import english from "./locales/en.json" with { type: "json" };
import simplifiedChinese from "./locales/zh-Hans.json" with { type: "json" };
import traditionalChinese from "./locales/zh-Hant.json" with { type: "json" };
import japanese from "./locales/ja.json" with { type: "json" };

export const catalogs = Object.freeze({ en: english, "zh-Hans": simplifiedChinese, "zh-Hant": traditionalChinese, ja: japanese });
export const SUPPORTED_LOCALES = Object.freeze(["en", "zh-Hans", "zh-Hant", "ja"]);
export const LANGUAGE_OPTIONS = Object.freeze([
  { value: "system", label: "Follow system" },
  { value: "zh-Hans", label: "简体中文" },
  { value: "zh-Hant", label: "繁體中文" },
  { value: "en", label: "English" },
  { value: "ja", label: "日本語" },
]);

export function resolveLocale(preference = "system", languages = globalThis.navigator?.languages ?? []) {
  if (preference !== "system") {
    if (!SUPPORTED_LOCALES.includes(preference)) throw new RangeError("Unsupported display language");
    return preference;
  }
  for (const language of languages) {
    if (typeof language !== "string") continue;
    const parts = language.replaceAll("_", "-").toLowerCase().split("-");
    if (parts[0] === "en" || parts[0] === "ja") return parts[0];
    if (parts[0] === "zh") {
      if (parts.includes("hans")) return "zh-Hans";
      return parts.includes("hant") || parts.some((part) => ["tw", "hk", "mo"].includes(part)) ? "zh-Hant" : "zh-Hans";
    }
  }
  return "en";
}

let locale = resolveLocale();
export function getLocale() { return locale; }

export function setLocale(value) {
  if (!SUPPORTED_LOCALES.includes(value)) throw new RangeError("Unsupported display language");
  locale = value;
  if (globalThis.document?.documentElement) document.documentElement.lang = value;
}

/// Source-owned English messages are keys; profile names, protocol values and
/// server diagnostics never pass through this function. Parameters are plain
/// text. HTML callers must escape the entire result exactly once.
export function t(message, parameters = {}) {
  const catalog = catalogs[locale];
  const translated = Object.hasOwn(catalog, message) ? catalog[message] : message;
  return translated.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu, (_, name) => {
    if (!Object.hasOwn(parameters, name)) throw new TypeError(`Missing translation parameter: ${name}`);
    return String(parameters[name]);
  });
}

export function formatDate(value, options) {
  return new Intl.DateTimeFormat(locale, options).format(value);
}
