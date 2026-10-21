// These physical family names match the closed Rust FontFamily contract.
// Offer the host's bundled families without rewriting an already saved choice.
export const FONT_OPTIONS = Object.freeze([
  { value: "", label: "System" },
  { value: "Avenir Next", label: "Avenir Next" },
  { value: "SF Mono", label: "SF Mono" },
  { value: "Segoe UI", label: "Segoe UI" },
  { value: "Consolas", label: "Consolas" },
]);

const HOST_FONTS = Object.freeze({
  macos: {
    families: ["", "Avenir Next", "SF Mono"],
    sans: '"Avenir Next", "SF Pro Text", "Helvetica Neue", sans-serif',
    mono: '"SF Mono", Menlo, Consolas, monospace',
    system: '-apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif',
  },
  windows: {
    families: ["", "Segoe UI", "Consolas"],
    sans: '"Segoe UI", system-ui, sans-serif',
    mono: 'Consolas, ui-monospace, monospace',
    system: '"Segoe UI", system-ui, sans-serif',
  },
});

function hostFonts(operatingSystem, family) {
  if (!["macos", "windows"].includes(operatingSystem)) throw new TypeError("host operating system is invalid");
  if (!FONT_OPTIONS.some((option) => option.value === family)) throw new TypeError("font family is invalid");
  return HOST_FONTS[operatingSystem];
}

export function platformFontOptions(operatingSystem, family) {
  const host = hostFonts(operatingSystem, family);
  return FONT_OPTIONS.filter((option) => host.families.includes(option.value) || option.value === family);
}

export function platformFontStyles(operatingSystem, family) {
  const host = hostFonts(operatingSystem, family);
  return {
    "--sans": family ? `"${family}", ${host.sans}` : host.sans,
    "--mono": host.mono,
    "--system-sans": host.system,
  };
}
