// Keys and summaries of provider update and health-check results.

export function providerActionKey(scope, name) {
  return `${scope}:${name}`;
}

export function providerBatchSummary(label, result) {
  const requested = Number(result?.requested ?? 0);
  const succeeded = result?.succeeded?.length ?? 0;
  const failed = result?.failed?.length ?? 0;
  const failures = (result?.failed ?? []).slice(0, 3).map((item) => `${item.name}: ${item.error}`).join("; ");
  return `${label}: ${succeeded}/${requested} succeeded${failed ? `, ${failed} failed${failures ? ` (${failures})` : ""}` : ""}`;
}

export function providerBatchSucceeded(result) {
  const requested = Number(result?.requested);
  return Number.isInteger(requested)
    && requested >= 0
    && (result?.failed?.length ?? 0) === 0
    && (result?.succeeded?.length ?? 0) === requested;
}
