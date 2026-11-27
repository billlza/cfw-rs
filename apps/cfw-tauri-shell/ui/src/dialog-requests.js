/// The order in which the dialogs that read before they open were asked
/// for: the network settings form and the one for shortcuts and network
/// rules, which close the others as they open, and those that show what
/// they have read, which are the review of unused credentials, the network
/// interfaces, the configuration preview, the migration of a legacy profile
/// and the subscription URL of an invalid profile. Such a dialog opens when
/// its read ends. By then another may have been asked for, or may be open
/// with what the user has entered there, so only the one that was asked for
/// last opens, and only while no overlay is open that opened during its
/// read. One that is overtaken opens nothing, also when the later one fails.
///
/// A dialog that opens at once, a confirmation, the menu of a profile or the
/// DNS query, is not counted. It is one of the overlays a read looks at when
/// it ends, so none opens over it, and one that was closed by then takes
/// nothing from the read. Connection Info opens at once but is none of those
/// overlays, so it asks for a dialog as it opens. A read looks at it as at
/// those overlays while the Connections page shows it, also once the page
/// shows it again after another page or panel was shown.
///
/// The count is kept in the state of the page, which those dialogs share.

/// The overlays of the page that are open: the menu of a profile, a dialog of
/// a feature, and the two settings forms.
export function openOverlays(state) {
  return [state.profileContextMenu, state.glassDialog, state.runtimeSettingsDialog, state.automationDialog]
    .filter((overlay) => overlay != null);
}

/// Notes that a dialog is asked for now. The answer says whether it may still
/// open: it is the one that was asked for last, and every overlay that is
/// open, and Connection Info if the page shows it, was open when it was asked
/// for.
export function askForDialog(state) {
  const asked = (state.dialogRequests ?? 0) + 1;
  state.dialogRequests = asked;
  const open = openDialogs(state);
  return () => state.dialogRequests === asked && openDialogs(state).every((dialog) => open.includes(dialog));
}

/// The dialogs a read looks at: the open overlays, and Connection Info while
/// the live panel of the Connections page shows it, which is while its
/// connection is one of those the page lists. Info stands for the connection
/// it shows, which every snapshot of the connections lists anew.
function openDialogs(state) {
  const overlays = openOverlays(state);
  if (state.activePage !== "connections" || state.connectionPanel === "diagnostics") return overlays;
  const shown = state.connections.some((connection) => connection.id === state.connectionDetailId);
  return shown ? [...overlays, `connection ${state.connectionDetailId}`] : overlays;
}

/// For what opens a dialog only when its read says so. It asks for none yet,
/// and the answer says whether none was asked for since.
export function watchDialogRequests(state) {
  const seen = state.dialogRequests ?? 0;
  return () => (state.dialogRequests ?? 0) === seen;
}
