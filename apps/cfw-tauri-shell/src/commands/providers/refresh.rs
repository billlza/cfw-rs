use super::*;
use tauri::{AppHandle, Manager};

impl ManagedProviders {
    pub(crate) fn stop_refresh(&self) -> Result<(), String> {
        if let Some(task) = self
            .refresh_task
            .lock()
            .map_err(|_| "provider refresh task lock is unavailable")?
            .take()
        {
            task.abort();
        }
        Ok(())
    }

    fn due_requests(
        &self,
        stored: &StoredProfile,
        time: u64,
    ) -> Result<Vec<ProviderRequest>, String> {
        let Some(catalog) = stored.profile.providers() else {
            return Ok(Vec::new());
        };
        let status = self.synchronized(stored)?;
        let mut requests = Vec::new();
        for kind in [ProviderKind::Proxy, ProviderKind::Rule] {
            for request in stored_provider_requests(&stored.profile, kind, None)? {
                let interval = match kind {
                    ProviderKind::Proxy => catalog
                        .proxies
                        .iter()
                        .find(|provider| provider.name == request.name)
                        .map(|provider| provider.source.interval_seconds),
                    ProviderKind::Rule => catalog
                        .rules
                        .iter()
                        .find(|provider| provider.name == request.name)
                        .map(|provider| provider.source.interval_seconds),
                }
                .ok_or("scheduled provider disappeared")?;
                let state = status
                    .iter()
                    .find(|(key, _)| key.kind == kind && key.name == request.name)
                    .map(|(_, state)| state)
                    .ok_or("scheduled provider state is missing")?;
                if time.saturating_sub(state.updated) >= u64::from(interval)
                    && time.saturating_sub(state.attempted) >= 60
                {
                    requests.push(request);
                }
            }
        }
        Ok(requests)
    }
}

pub(crate) fn start_provider_refresh(app: AppHandle) -> Result<(), String> {
    let manager = app.state::<ManagedProviders>();
    let mut task = manager
        .refresh_task
        .lock()
        .map_err(|_| "provider refresh task lock is unavailable")?;
    if task.is_some() {
        return Ok(());
    }
    let handle = app.clone();
    *task = Some(tauri::async_runtime::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut previous_error = None;
        loop {
            timer.tick().await;
            let engine = handle.state::<ManagedEngine>();
            // Remote intervals belong to a selected running profile. Stop does
            // not trigger background traffic or start a replacement runtime.
            if super::super::controller::controller_client(&engine).is_err() {
                continue;
            }
            let profiles = handle.state::<ManagedProfiles>();
            let providers = handle.state::<ManagedProviders>();
            if providers.update.try_lock().is_err() {
                continue;
            }
            let operation = async {
                let stored = selected(&profiles).await?;
                let requests = providers.due_requests(&stored, now()?)?;
                if requests.is_empty() {
                    return Ok(());
                }
                update_resources(
                    &engine,
                    &handle.state::<LegacyRetirementGate>(),
                    &profiles,
                    &providers,
                    stored,
                    requests,
                )
                .await
                .map(|_| ())
            }
            .await;
            match operation {
                Ok(()) => previous_error = None,
                Err(error) => {
                    if previous_error.as_ref() != Some(&error) {
                        eprintln!("provider refresh failed: {error}");
                    }
                    previous_error = Some(error);
                }
            }
        }
    }));
    Ok(())
}
