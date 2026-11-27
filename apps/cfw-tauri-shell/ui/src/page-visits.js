/// The page the app shows, as `activePage`, and `pageVisit`, which counts the
/// times another page was shown since. What is asked for on one page and ends
/// later, the read of Reload From Disk for one, compares the visit: the user
/// may have left that page and come back to it meanwhile, and its name would
/// be the same. Showing the page that is shown begins no visit.
export function trackPageVisits(target, page) {
  let shown = page;
  let visit = 0;
  return Object.defineProperties(target, {
    activePage: {
      enumerable: true,
      get: () => shown,
      set: (next) => {
        if (next === shown) return;
        shown = next;
        visit += 1;
      },
    },
    pageVisit: { enumerable: true, get: () => visit },
  });
}
