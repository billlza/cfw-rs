export function formatTimestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

export function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ["KiB", "MiB", "GiB"];
  let amount = bytes / 1024;
  let unit = units[0];
  for (let index = 1; amount >= 1024 && index < units.length; index += 1) {
    amount /= 1024;
    unit = units[index];
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${unit}`;
}

export function errorMessage(error) {
  if (error instanceof Error && error.message) return redactDiagnosticText(error.message);
  if (typeof error === "string" && error.trim()) return redactDiagnosticText(error);
  return "An unknown error occurred.";
}

export function formatUpdateProgress(payload) {
  if (payload?.phase === "stopping-network") {
    return "Stopping the network engine before installing the update";
  }
  const downloaded = Number(payload?.downloaded);
  const total = Number(payload?.total);
  if (!Number.isFinite(downloaded) || downloaded < 0) return null;
  return Number.isFinite(total) && total > 0
    ? `Downloaded ${downloaded} of ${total} bytes`
    : `Downloaded ${downloaded} bytes`;
}

export function profileUpdatedLabel(epochSeconds) {
  const seconds = Number(epochSeconds);
  if (!Number.isFinite(seconds) || seconds <= 0) return "Never updated";
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? "Never updated" : date.toLocaleString();
}
export function redactDiagnosticText(value) {
  return String(value)
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, "$1[redacted]")
    .replace(/([?&](?:token|key|secret|password|auth|sig|signature|x-amz-[a-z0-9-]+|se|sp|sv)=)[^&\s]+/giu, "$1[redacted]")
    .replace(/\b(token|secret|password|authorization|sig|signature|x-amz-[a-z0-9-]+|se|sp|sv)\s*[:=]\s*[^&\s,;]+/giu, "$1=[redacted]");
}
