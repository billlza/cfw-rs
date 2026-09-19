//! Native-shell ownership of persisted dashboard geometry.
//!
//! The renderer owns only the `retain_window_bounds` preference. Physical
//! geometry, monitor selection, debounce and persistence stay in this module so
//! no web content can choose an arbitrary platform-window position or path.

use std::sync::Mutex;
use std::time::Duration;

use cfw_core::WindowBounds;
use cfw_engine_api::EngineEvent;
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, WindowEvent};

use crate::settings_store;

const MAIN_WINDOW_LABEL: &str = "main";
const MIN_WINDOW_WIDTH: u32 = 850;
const MIN_WINDOW_HEIGHT: u32 = 603;
const WINDOW_BOUNDS_DEBOUNCE: Duration = Duration::from_millis(350);

pub(crate) struct WindowBoundsManager {
    state: Mutex<RetentionState>,
    persistence: tokio::sync::Mutex<()>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl Default for WindowBoundsManager {
    fn default() -> Self {
        Self {
            state: Mutex::new(RetentionState::default()),
            persistence: tokio::sync::Mutex::new(()),
            changes: tokio::sync::watch::channel(0).0,
        }
    }
}

#[derive(Default)]
struct RetentionState {
    enabled: bool,
    revision: u64,
    worker_started: bool,
}

impl RetentionState {
    fn invalidate_capture(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    fn reserve_capture(&mut self) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        self.invalidate_capture();
        Some(self.revision)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkArea {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

impl WindowBoundsManager {
    fn configure(&self, enabled: bool) -> Result<(), String> {
        let mut state = self.lock()?;
        state.enabled = enabled;
        state.invalidate_capture();
        self.changes.send_replace(state.revision);
        Ok(())
    }

    /// Disk serialization is async and distinct from the short in-memory lock
    /// used by AppKit events. An in-flight write is never aborted mid-I/O.
    pub(crate) async fn commit_retention<T: Send + 'static>(
        &self,
        app: &AppHandle,
        enabled: bool,
        operation: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let value = self.persist_retention(enabled, operation).await?;
        if enabled {
            self.schedule(app.clone())?;
        }
        Ok(value)
    }

    async fn persist_retention<T: Send + 'static>(
        &self,
        enabled: bool,
        operation: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let _persistence = self.persistence.lock().await;
        let value = crate::startup_state::prepare_off_main(operation).await?;
        self.configure(enabled)?;
        Ok(value)
    }

    pub(crate) fn schedule(&self, app: AppHandle) -> Result<(), String> {
        let start_worker = {
            let mut state = self.lock()?;
            let Some(revision) = state.reserve_capture() else {
                return Ok(());
            };
            self.changes.send_replace(revision);
            let start = !state.worker_started;
            state.worker_started = true;
            start
        };
        if start_worker {
            let mut changes = self.changes.subscribe();
            tauri::async_runtime::spawn(async move {
                loop {
                    let revision = *changes.borrow_and_update();
                    tokio::select! {
                        _ = tokio::time::sleep(WINDOW_BOUNDS_DEBOUNCE) => {},
                        changed = changes.changed() => {
                            if changed.is_err() { return; }
                            continue;
                        }
                    }
                    let manager = app.state::<WindowBoundsManager>();
                    if let Err(error) = manager.capture_and_persist(&app, revision).await {
                        publish_window_state_error(&app, "window_bounds_persist_failed", error);
                    }
                    if changes.changed().await.is_err() {
                        return;
                    }
                }
            });
        }
        Ok(())
    }

    pub(crate) async fn flush(&self, app: &AppHandle) -> Result<(), String> {
        let revision = {
            let mut state = self.lock()?;
            let Some(revision) = state.reserve_capture() else {
                return Ok(());
            };
            revision
        };
        self.capture_and_persist(app, revision).await
    }

    async fn capture_and_persist(&self, app: &AppHandle, revision: u64) -> Result<(), String> {
        let _persistence = self.persistence.lock().await;
        {
            let state = self.lock()?;
            if !state.enabled || state.revision != revision {
                return Ok(());
            }
        }
        let bounds = current_main_window_bounds(app)?;
        crate::startup_state::prepare_off_main(move || {
            settings_store()?
                .write_window_bounds(bounds)
                .map_err(|error| error.to_string())
        })
        .await
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RetentionState>, String> {
        self.state
            .lock()
            .map_err(|_| "window bounds retention state is unavailable".to_owned())
    }
}

pub(crate) struct InitialWindowSettings {
    pub(crate) silent_start: bool,
    retained: bool,
    bounds: Result<Option<WindowBounds>, String>,
}

pub(crate) fn load_initial_window_settings() -> Result<InitialWindowSettings, String> {
    let store = settings_store()?;
    let preferences = store.read_or_default().map_err(|error| error.to_string())?;
    let bounds = load_retained_bounds(preferences.retain_window_bounds, || {
        store.window_bounds().map_err(|error| error.to_string())
    });
    Ok(InitialWindowSettings {
        silent_start: preferences.silent_start,
        retained: preferences.retain_window_bounds,
        bounds,
    })
}

pub(crate) fn restore_initial_window_bounds(
    app: &AppHandle,
    settings: &InitialWindowSettings,
    explicitly_opened: bool,
) -> Result<(), String> {
    let manager = app.state::<WindowBoundsManager>();
    manager.configure(settings.retained)?;
    if !explicitly_opened {
        let Some(saved) = settings.bounds.clone()? else {
            return Ok(());
        };
        let window = app
            .get_webview_window(MAIN_WINDOW_LABEL)
            .ok_or_else(|| "main window is unavailable while restoring bounds".to_owned())?;
        let work_areas = window
            .available_monitors()
            .map_err(|error| format!("available monitors could not be observed: {error}"))?
            .into_iter()
            .map(|monitor| {
                let area = monitor.work_area();
                WorkArea {
                    x: area.position.x,
                    y: area.position.y,
                    width: area.size.width,
                    height: area.size.height,
                }
            })
            .collect::<Vec<_>>();
        let visible = clamp_to_visible_work_area(saved, &work_areas)?;
        window
            .set_size(PhysicalSize::new(visible.width, visible.height))
            .map_err(|error| format!("restored window size was rejected: {error}"))?;
        window
            .set_position(PhysicalPosition::new(visible.x, visible.y))
            .map_err(|error| format!("restored window position was rejected: {error}"))?;
    }
    manager.schedule(app.clone())
}

fn load_retained_bounds(
    retained: bool,
    load: impl FnOnce() -> Result<Option<WindowBounds>, String>,
) -> Result<Option<WindowBounds>, String> {
    if retained { load() } else { Ok(None) }
}

pub(crate) fn handle_window_bounds_event(
    app: &AppHandle,
    window_label: &str,
    event: &WindowEvent,
) -> Result<(), String> {
    if window_label != MAIN_WINDOW_LABEL {
        return Ok(());
    }
    if matches!(
        event,
        WindowEvent::Moved(_) | WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. }
    ) {
        app.state::<WindowBoundsManager>().schedule(app.clone())?;
    }
    Ok(())
}

fn current_main_window_bounds(app: &AppHandle) -> Result<WindowBounds, String> {
    let window = app
        .get_webview_window(MAIN_WINDOW_LABEL)
        .ok_or_else(|| "main window is unavailable while saving bounds".to_owned())?;
    let position = window
        .outer_position()
        .map_err(|error| format!("main window position could not be observed: {error}"))?;
    // Tauri's configured width/height and `set_size` both describe the inner
    // content size. Persisting `outer_size` here would add the title-bar inset on
    // every restore and make the window grow across launches.
    let size = window
        .inner_size()
        .map_err(|error| format!("main window size could not be observed: {error}"))?;
    WindowBounds::new(position.x, position.y, size.width, size.height)
        .map_err(|error| error.to_string())
}

fn clamp_to_visible_work_area(
    saved: WindowBounds,
    work_areas: &[WorkArea],
) -> Result<WindowBounds, String> {
    let usable = work_areas
        .iter()
        .copied()
        .filter(|area| area.width != 0 && area.height != 0)
        .collect::<Vec<_>>();
    let target = usable
        .iter()
        .max_by_key(|area| {
            let intersection = intersection_area(saved, **area);
            let distance = center_distance_squared(saved, **area);
            (intersection, std::cmp::Reverse(distance))
        })
        .copied()
        .ok_or_else(|| "no usable monitor work area is available".to_owned())?;

    let width = saved.width.max(MIN_WINDOW_WIDTH).min(target.width);
    let height = saved.height.max(MIN_WINDOW_HEIGHT).min(target.height);
    let minimum_x = i64::from(target.x);
    let minimum_y = i64::from(target.y);
    let maximum_x = minimum_x + i64::from(target.width.saturating_sub(width));
    let maximum_y = minimum_y + i64::from(target.height.saturating_sub(height));
    let x = i64::from(saved.x).clamp(minimum_x, maximum_x);
    let y = i64::from(saved.y).clamp(minimum_y, maximum_y);
    WindowBounds::new(
        i32::try_from(x).map_err(|_| "clamped window x coordinate exceeds i32".to_owned())?,
        i32::try_from(y).map_err(|_| "clamped window y coordinate exceeds i32".to_owned())?,
        width,
        height,
    )
    .map_err(|error| error.to_string())
}

fn intersection_area(bounds: WindowBounds, area: WorkArea) -> u64 {
    let left = i64::from(bounds.x).max(i64::from(area.x));
    let top = i64::from(bounds.y).max(i64::from(area.y));
    let right = (i64::from(bounds.x) + i64::from(bounds.width))
        .min(i64::from(area.x) + i64::from(area.width));
    let bottom = (i64::from(bounds.y) + i64::from(bounds.height))
        .min(i64::from(area.y) + i64::from(area.height));
    let width = right.saturating_sub(left).max(0) as u64;
    let height = bottom.saturating_sub(top).max(0) as u64;
    width.saturating_mul(height)
}

fn center_distance_squared(bounds: WindowBounds, area: WorkArea) -> u128 {
    let bounds_x = i128::from(bounds.x) * 2 + i128::from(bounds.width);
    let bounds_y = i128::from(bounds.y) * 2 + i128::from(bounds.height);
    let area_x = i128::from(area.x) * 2 + i128::from(area.width);
    let area_y = i128::from(area.y) * 2 + i128::from(area.height);
    (bounds_x - area_x).unsigned_abs().pow(2) + (bounds_y - area_y).unsigned_abs().pow(2)
}

fn publish_window_state_error(app: &AppHandle, code: &str, message: String) {
    if let Err(error) = app.emit(
        "cfw://engine-event",
        EngineEvent::boundary_failure(code, message),
    ) {
        eprintln!("failed to publish window state error: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_blocked_settings_write_never_holds_the_window_event_lock() {
        use cfw_core::{MacOsAppPaths, SettingsStore, UiPreferences};
        use std::os::fd::AsRawFd;
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        let store = SettingsStore::new(MacOsAppPaths::from_app_home(root.path().join("app")));
        store.write(&UiPreferences::default()).unwrap();
        let file_lock = std::fs::File::open(&store.paths().app_home).unwrap();
        assert_eq!(
            unsafe { libc::flock(file_lock.as_raw_fd(), libc::LOCK_EX) },
            0
        );
        let manager = Arc::new(WindowBoundsManager::default());
        manager.configure(true).unwrap();
        let writer = manager.clone();
        let (entered, entered_io) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            writer
                .persist_retention(false, move || {
                    entered.send(()).unwrap();
                    store
                        .write(&UiPreferences {
                            retain_window_bounds: false,
                            ..UiPreferences::default()
                        })
                        .map_err(|error| error.to_string())
                })
                .await
        });
        entered_io.await.unwrap();
        let observer = manager.clone();
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let observer = std::thread::spawn(move || {
            let revision = observer.lock().unwrap().reserve_capture();
            sent.send(revision).unwrap();
        });
        let observed = received.recv_timeout(Duration::from_millis(500));
        drop(file_lock);
        task.await.unwrap().unwrap();
        observer.join().unwrap();
        assert!(
            matches!(observed, Ok(Some(_))),
            "AppKit events waited on a blocked filesystem write"
        );
        assert!(!manager.lock().unwrap().enabled);
    }

    #[tokio::test]
    async fn failed_preference_write_preserves_the_existing_retention_policy() {
        let manager = WindowBoundsManager::default();
        manager.configure(true).unwrap();
        assert_eq!(
            manager
                .persist_retention(false, || Err::<(), _>("disk error".into()))
                .await,
            Err("disk error".into())
        );
        assert!(manager.lock().unwrap().enabled);
    }

    fn bounds(x: i32, y: i32, width: u32, height: u32) -> WindowBounds {
        WindowBounds::new(x, y, width, height).expect("valid test bounds")
    }

    #[test]
    fn visible_bounds_are_preserved() {
        let saved = bounds(100, 120, 1000, 700);
        let displays = [WorkArea {
            x: 0,
            y: 25,
            width: 1728,
            height: 1080,
        }];
        assert_eq!(clamp_to_visible_work_area(saved, &displays).unwrap(), saved);
    }

    #[test]
    fn removed_display_bounds_move_to_the_nearest_visible_work_area() {
        let saved = bounds(-1800, 100, 1200, 800);
        let displays = [
            WorkArea {
                x: 0,
                y: 25,
                width: 1728,
                height: 1080,
            },
            WorkArea {
                x: 1728,
                y: 25,
                width: 1920,
                height: 1055,
            },
        ];
        assert_eq!(
            clamp_to_visible_work_area(saved, &displays).unwrap(),
            bounds(0, 100, 1200, 800)
        );
    }

    #[test]
    fn oversized_or_offscreen_bounds_are_shrunk_and_fully_clamped() {
        let saved = bounds(9_000, -4_000, 4_000, 3_000);
        let displays = [WorkArea {
            x: -1920,
            y: 25,
            width: 1920,
            height: 1055,
        }];
        assert_eq!(
            clamp_to_visible_work_area(saved, &displays).unwrap(),
            bounds(-1920, 25, 1920, 1055)
        );
    }

    #[test]
    fn display_with_largest_overlap_wins_during_topology_change() {
        let saved = bounds(1600, 100, 1000, 700);
        let displays = [
            WorkArea {
                x: 0,
                y: 25,
                width: 1728,
                height: 1080,
            },
            WorkArea {
                x: 1728,
                y: 25,
                width: 1920,
                height: 1055,
            },
        ];
        assert_eq!(
            clamp_to_visible_work_area(saved, &displays).unwrap(),
            bounds(1728, 100, 1000, 700)
        );
    }

    #[test]
    fn empty_or_zero_sized_monitor_set_is_rejected() {
        assert!(clamp_to_visible_work_area(bounds(0, 0, 850, 603), &[]).is_err());
        assert!(
            clamp_to_visible_work_area(
                bounds(0, 0, 850, 603),
                &[WorkArea {
                    x: 0,
                    y: 0,
                    width: 0,
                    height: 0,
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn disabled_retention_never_reads_or_reserves_a_geometry_write() {
        let mut state = RetentionState::default();
        assert_eq!(state.reserve_capture(), None);
        let loaded = std::cell::Cell::new(false);
        assert_eq!(
            load_retained_bounds(false, || {
                loaded.set(true);
                Ok(Some(bounds(0, 0, 850, 603)))
            })
            .unwrap(),
            None
        );
        assert!(!loaded.get());
    }

    #[test]
    fn enabled_retention_uses_a_single_debounced_revision() {
        let mut state = RetentionState {
            enabled: true,
            ..RetentionState::default()
        };
        let first = state.reserve_capture().expect("first capture");
        let second = state.reserve_capture().expect("replacement capture");
        assert_ne!(first, second);
        assert_eq!(WINDOW_BOUNDS_DEBOUNCE, Duration::from_millis(350));
    }
}
