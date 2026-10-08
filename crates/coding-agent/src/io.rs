use crate::types::{Journal, MAX_FILE_BYTES, MAX_JOURNAL_BYTES};
use crate::Error;
use agent_sdk::{KernelClient, WorkspaceKind, WorkspaceOpenRequest, WorkspaceRight};
use chrono::Utc;
use std::future::Future;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct JobIo {
    pub client: KernelClient,
    pub control: KernelClient,
    pub cancel: CancellationToken,
    pub steps: u32,
    max_steps: u32,
    deadline: chrono::DateTime<Utc>,
    poisoned: bool,
}
impl JobIo {
    pub async fn read_optional_file(
        &mut self,
        agent: Uuid,
        path: &str,
    ) -> Result<Option<String>, Error> {
        crate::types::safe_path(path)?;
        let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
        let mount = if directory.is_empty() {
            "/workspace".into()
        } else {
            format!("/workspace/{directory}")
        };
        let duration = self.step()?;
        let result = Self::wait(
            duration,
            self.cancel.clone(),
            self.client.vfs_open_workspace(
                agent.to_string(),
                WorkspaceOpenRequest {
                    path: mount,
                    kind: WorkspaceKind::Directory,
                    rights: vec![WorkspaceRight::List],
                    allow_missing: false,
                },
            ),
        )
        .await;
        let handle = self.observe(result)?;
        let result = async {
            let duration = self.step()?;
            let result = Self::wait(
                duration,
                self.cancel.clone(),
                self.client
                    .vfs_list_workspace(agent.to_string(), &handle.id),
            )
            .await;
            self.observe(result)
        }
        .await;
        let _ = self.control.vfs_close(agent.to_string(), &handle.id).await;
        let listing = result?;
        let entries = listing["entries"]
            .as_array()
            .ok_or_else(|| Error::Contract("directory listing has no bounded entries".into()))?;
        if entries.iter().any(|entry| entry.as_str() == Some(name)) {
            self.read_file(agent, path).await.map(Some)
        } else {
            Ok(None)
        }
    }
    pub fn new(
        client: KernelClient,
        control: KernelClient,
        journal: &Journal,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            client,
            control,
            cancel,
            steps: journal.steps,
            max_steps: journal.spec.max_steps,
            deadline: journal.created
                + chrono::Duration::seconds(journal.spec.deadline_seconds as i64),
            poisoned: false,
        }
    }
    pub fn step(&mut self) -> Result<Duration, Error> {
        if self.poisoned {
            return Err(Error::Uncertain("transport operation".into()));
        }
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let remaining = (self.deadline - Utc::now())
            .to_std()
            .map_err(|_| Error::Budget("deadline".into()))?;
        if remaining.is_zero() || self.steps >= self.max_steps {
            return Err(Error::Budget("deadline or request count".into()));
        }
        self.steps += 1;
        Ok(remaining.min(Duration::from_secs(60)))
    }
    pub(crate) async fn wait<T>(
        duration: Duration,
        cancel: CancellationToken,
        future: impl Future<Output = Result<T, agent_sdk::SdkError>>,
    ) -> Result<T, Error> {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::Cancelled),
            result = tokio::time::timeout(duration, future) => result.map_err(|_| Error::Budget("request deadline".into()))?.map_err(Error::Sdk),
        }
    }
    pub(crate) fn observe<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if matches!(&result, Err(Error::Cancelled | Error::Budget(_))) {
            self.poisoned = true;
        }
        result
    }
    pub async fn read_file(&mut self, agent: Uuid, path: &str) -> Result<String, Error> {
        crate::types::safe_path(path)?;
        let duration = self.step()?;
        let request = WorkspaceOpenRequest {
            path: format!("/workspace/{path}"),
            kind: WorkspaceKind::File,
            rights: vec![WorkspaceRight::Read, WorkspaceRight::Stat],
            allow_missing: false,
        };
        let result = Self::wait(
            duration,
            self.cancel.clone(),
            self.client.vfs_open_workspace(agent.to_string(), request),
        )
        .await;
        let handle = self.observe(result)?;
        let result = self.read_handle(agent, &handle.id).await;
        let _ = self.control.vfs_close(agent.to_string(), &handle.id).await;
        result
    }
    async fn read_handle(&mut self, agent: Uuid, handle: &str) -> Result<String, Error> {
        let duration = self.step()?;
        let result = Self::wait(
            duration,
            self.cancel.clone(),
            self.client.vfs_stat_workspace(agent.to_string(), handle),
        )
        .await;
        let stat = self.observe(result)?;
        if stat.size > MAX_FILE_BYTES as u64 {
            return Err(Error::Contract("file exceeds task byte bound".into()));
        }
        let mut bytes = Vec::with_capacity(stat.size as usize);
        loop {
            let duration = self.step()?;
            let result = Self::wait(
                duration,
                self.cancel.clone(),
                self.client
                    .vfs_read_bytes(agent.to_string(), handle, bytes.len() as u64, 4096),
            )
            .await;
            let chunk = self.observe(result)?;
            if chunk.offset != bytes.len() as u64
                || bytes.len() + chunk.bytes.len() > MAX_FILE_BYTES
            {
                return Err(Error::Contract("file changed or exceeded its bound".into()));
            }
            let count = chunk.bytes.len();
            bytes.extend(chunk.bytes);
            if chunk.eof {
                break;
            }
            if count == 0 {
                return Err(Error::Contract("workspace read made no progress".into()));
            }
        }
        String::from_utf8(bytes)
            .map_err(|_| Error::Contract("only UTF-8 source files are supported".into()))
    }
    pub async fn write_file(
        &mut self,
        agent: Uuid,
        path: &str,
        content: &str,
    ) -> Result<(), Error> {
        crate::types::safe_path(path)?;
        if content.len() > MAX_FILE_BYTES {
            return Err(Error::Contract("write exceeds task byte bound".into()));
        }
        let duration = self.step()?;
        let result = Self::wait(
            duration,
            self.cancel.clone(),
            self.client.vfs_open_workspace(
                agent.to_string(),
                WorkspaceOpenRequest {
                    path: format!("/workspace/{path}"),
                    kind: WorkspaceKind::File,
                    rights: vec![WorkspaceRight::Write],
                    allow_missing: true,
                },
            ),
        )
        .await;
        let handle = self.observe(result)?;
        let result = async {
            let duration = self.step()?;
            let result = Self::wait(
                duration,
                self.cancel.clone(),
                self.client
                    .vfs_write_bytes(agent.to_string(), &handle.id, content.as_bytes()),
            )
            .await;
            self.observe(result).map(|_| ())
        }
        .await;
        let _ = self.control.vfs_close(agent.to_string(), &handle.id).await;
        result
    }
    pub async fn mkdir(&mut self, agent: Uuid, path: &str) -> Result<(), Error> {
        crate::types::safe_path(path)?;
        let duration = self.step()?;
        let result = Self::wait(
            duration,
            self.cancel.clone(),
            self.client
                .vfs_open(agent.to_string(), "/tools/create_directory"),
        )
        .await;
        let handle = self.observe(result)?;
        let result = async {
            let duration = self.step()?;
            let result = Self::wait(
                duration,
                self.cancel.clone(),
                self.client.vfs_invoke(
                    agent.to_string(),
                    &handle.id,
                    serde_json::json!({"path":path}),
                ),
            )
            .await;
            self.observe(result).map(|_| ())
        }
        .await;
        let _ = self.control.vfs_close(agent.to_string(), &handle.id).await;
        result
    }
    pub async fn persist(&mut self, journal: &mut Journal) -> Result<(), Error> {
        let duration = self.step()?;
        let result = Self::wait(
            duration,
            self.cancel.clone(),
            self.client.vfs_open_kv(
                journal.parent.to_string(),
                "/kv",
                &format!("coding-job:{}", journal.id),
                vec![WorkspaceRight::Read, WorkspaceRight::Write],
            ),
        )
        .await;
        let handle = self.observe(result)?;
        let result = async {
            let duration = self.step()?;
            journal.steps = self.steps;
            let value = serde_json::to_string(journal)?;
            if value.len() > MAX_JOURNAL_BYTES {
                return Err(Error::Contract("journal exceeds task byte bound".into()));
            }
            let result = Self::wait(
                duration,
                self.cancel.clone(),
                self.client.vfs_write_data(
                    journal.parent.to_string(),
                    &handle.id,
                    serde_json::json!({"value":value}),
                ),
            )
            .await;
            self.observe(result).map(|_| ())
        }
        .await;
        let _ = self
            .control
            .vfs_close(journal.parent.to_string(), &handle.id)
            .await;
        if result.is_ok() {
            if let Some(event) = journal.events.last() {
                eprintln!("{}", serde_json::to_string(event)?);
            }
        }
        result
    }
    pub async fn emergency_persist(&mut self, journal: &mut Journal) -> Result<(), Error> {
        journal.steps = self.steps;
        let value = serde_json::to_string(journal)?;
        if value.len() > MAX_JOURNAL_BYTES {
            return Err(Error::Contract("journal exceeds task byte bound".into()));
        }
        let handle = self
            .control
            .vfs_open_kv(
                journal.parent.to_string(),
                "/kv",
                &format!("coding-job:{}", journal.id),
                vec![WorkspaceRight::Write],
            )
            .await?;
        let result = self
            .control
            .vfs_write_data(
                journal.parent.to_string(),
                &handle.id,
                serde_json::json!({"value":value}),
            )
            .await;
        let _ = self
            .control
            .vfs_close(journal.parent.to_string(), &handle.id)
            .await;
        result.map(|_| ()).map_err(Error::Sdk)
    }
    pub async fn load(
        client: &mut KernelClient,
        parent: Uuid,
        job: Uuid,
    ) -> Result<Journal, Error> {
        let handle = client
            .vfs_open_kv(
                parent.to_string(),
                "/kv",
                &format!("coding-job:{job}"),
                vec![WorkspaceRight::Read],
            )
            .await?;
        let result = client
            .vfs_read_data(parent.to_string(), &handle.id, serde_json::json!({}))
            .await;
        let _ = client.vfs_close(parent.to_string(), &handle.id).await;
        let value = result?;
        let text = value["value"]
            .as_str()
            .ok_or_else(|| Error::Contract("job journal not found".into()))?;
        if text.len() > MAX_JOURNAL_BYTES {
            return Err(Error::Contract("journal exceeds task byte bound".into()));
        }
        let journal: Journal = serde_json::from_str(text)?;
        journal.validate()?;
        if journal.id != job || journal.parent != parent {
            return Err(Error::Contract("journal identity mismatch".into()));
        }
        Ok(journal)
    }
}
