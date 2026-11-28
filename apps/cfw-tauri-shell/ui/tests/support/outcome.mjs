// What became of a promise that the code under test may leave pending, for a
// test that must fail where a defect leaves it so, and not wait for good.

/// What became of `press` once all that follows from the answers given so far
/// has run. A press that waits for an answer no one gives is "still waiting",
/// where a test that awaited the press itself would never end.
export const outcome = (press) => Promise.race([press, new Promise((resolve) => { setImmediate(resolve, "still waiting"); })]);
