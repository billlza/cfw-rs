// Local source admission only. Parsing and credential extraction remain in
// the native import boundary; source text never enters the renderer store.
export const MAX_PROFILE_SOURCE_BYTES = 4 * 1024 * 1024;
export const PROFILE_SOURCE_ACCEPT = ".json,.yaml,.yml,.conf,.txt,application/json,text/yaml,text/plain";

export function isSubscriptionSource(source) {
  if (!/^https?:\/\//iu.test(source)) return false;
  try {
    const parsed = new URL(source);
    // An explicit Basic identity or node label identifies an HTTP proxy link.
    // Plain HTTPS links remain subscriptions; bare proxy endpoints can be
    // imported as JSON/YAML or given a #node-name fragment.
    return !parsed.username && !parsed.password && !parsed.hash;
  } catch { return true; }
}

export function isProfileSourcePath(path) {
  return /\.(?:json|yaml|yml|conf|txt)$/iu.test(path);
}

export async function readProfileSourceFile(file) {
  if (/\.xlsx?$/iu.test(file.name)) {
    throw new Error("Excel workbooks are not profile documents. Import the YAML/JSON file or paste its node link.");
  }
  if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > MAX_PROFILE_SOURCE_BYTES) {
    throw new Error(`Profile source exceeds the ${MAX_PROFILE_SOURCE_BYTES}-byte limit.`);
  }
  const bytes = await file.arrayBuffer();
  if (bytes.byteLength > MAX_PROFILE_SOURCE_BYTES) {
    throw new Error(`Profile source exceeds the ${MAX_PROFILE_SOURCE_BYTES}-byte limit.`);
  }
  // File.text() replaces malformed UTF-8 and can therefore alter credentials.
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
    throw new Error("Profile source must be UTF-8 JSON, YAML, WireGuard, or node-link text.");
  }
}
