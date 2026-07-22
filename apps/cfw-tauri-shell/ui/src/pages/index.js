import { renderAboutPage } from "./about.js";
import { renderGeneralPage } from "./general.js";
import { renderLogsPage } from "./logs.js";
import { renderProfilesPage } from "./profiles.js";
import { renderSettingsPage } from "./settings.js";

const RENDERERS = Object.freeze({
  general: renderGeneralPage,
  profiles: renderProfilesPage,
  settings: renderSettingsPage,
  logs: renderLogsPage,
  about: renderAboutPage,
});

export function renderPage(state) {
  const renderer = RENDERERS[state.activePage] ?? RENDERERS.general;
  return renderer(state);
}
