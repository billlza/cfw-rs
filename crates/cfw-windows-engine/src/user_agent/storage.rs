use super::{Result, UserAgentError, UserAgentRuntime};
use crate::{VerifiedExecutable, WindowsSystemProxy};
use cfw_engine_api::authority_v1::AuthorityMode;
use cfw_windows_storage::PrivateDirectory;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// Stable current-user storage supplied by the trusted installation. No path
/// comes from the start/recovery wire message. One engine directory and one
/// proxy journal are reused under the Authority's exclusive runtime lease.
/// Opening storage alone never authorizes activation or proves global cleanup.
pub struct UserRuntimeStorage {
    root: PathBuf,
    directory: Arc<PrivateDirectory>,
    proxy: WindowsSystemProxy,
}
impl UserRuntimeStorage {
    pub fn open(root: &Path) -> Result<Self> {
        crate::system_proxy::user_identity()?;
        let directory =
            Arc::new(PrivateDirectory::open_or_create(root).map_err(crate::Error::from)?);
        let proxy = WindowsSystemProxy::new(&root.join("proxy-v1"))?;
        Ok(Self {
            root: root.to_owned(),
            directory,
            proxy,
        })
    }
    pub fn proxy(&self) -> &WindowsSystemProxy {
        &self.proxy
    }
    pub fn runtime(
        &self,
        executable: VerifiedExecutable,
        mode: AuthorityMode,
    ) -> Result<UserAgentRuntime> {
        let proxy = match mode {
            AuthorityMode::LocalProxy => None,
            AuthorityMode::SystemProxy => Some(self.proxy.clone()),
            AuthorityMode::Tunnel => return Err(UserAgentError::Mode),
        };
        let mut runtime = UserAgentRuntime::new(executable, self.root.join("engine-v1"), proxy);
        runtime.storage = Some(Arc::clone(&self.directory));
        Ok(runtime)
    }
}
