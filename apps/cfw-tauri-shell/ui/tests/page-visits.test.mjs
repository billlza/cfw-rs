// The visits of pages: each page shown after another begins one, which what
// ends later on a page compares, as the name of the page is the same again
// once the user is back.
import test from "node:test";
import assert from "node:assert/strict";
import { trackPageVisits } from "../src/page-visits.js";
import { state } from "../src/state.js";

test("each page shown after another begins a visit, and the page that is shown begins none", () => {
  const page = trackPageVisits({ other: 1 }, "general");
  assert.deepEqual([page.activePage, page.pageVisit, page.other], ["general", 0, 1]);
  page.activePage = "general";
  assert.equal(page.pageVisit, 0);
  page.activePage = "settings";
  page.activePage = "general";
  assert.deepEqual([page.activePage, page.pageVisit], ["general", 2]);
  assert.throws(() => { page.pageVisit = 0; }, TypeError, "the count is only read");
  assert.deepEqual(Object.keys(page), ["other", "activePage", "pageVisit"]);
});

test("the state of the app counts the visits of its pages", () => {
  const before = state.pageVisit;
  const shown = state.activePage;
  state.activePage = shown === "settings" ? "general" : "settings";
  state.activePage = shown;
  assert.equal(state.pageVisit, before + 2);
  assert.equal(state.activePage, shown);
});
