//! Explicitly configured OpenAI-compatible and Ollama embedding transports.

use super::{Embedder, EmbeddingError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Read;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum HttpEmbeddingProtocol {
    OpenaiCompatible,
    Ollama,
}

/// Operator configuration contains credential references, never key values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEmbeddingConfig {
    pub protocol: HttpEmbeddingProtocol,
    /// Full embeddings URL; HTTPS, or explicit loopback HTTP for local services.
    pub endpoint: String,
    pub model: String,
    pub dimensions: usize,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub request_dimensions: bool,
    #[serde(default)]
    pub expected_response_model: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}
fn default_version() -> u32 {
    1
}
fn default_timeout() -> u64 {
    15
}
fn default_batch_size() -> usize {
    32
}

impl HttpEmbeddingConfig {
    pub fn validate(&self) -> Result<(), EmbeddingError> {
        let url = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| EmbeddingError::Configuration("invalid endpoint URL"))?;
        if url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(EmbeddingError::Configuration(
                "endpoint cannot contain credentials, query or fragment",
            ));
        }
        let local = url.host_str().is_some_and(|host| {
            host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
        });
        if url.scheme() != "https" && !(url.scheme() == "http" && local) {
            return Err(EmbeddingError::Configuration(
                "HTTPS is required except for loopback HTTP",
            ));
        }
        if url.host_str().is_none() || self.endpoint.len() > 2048 {
            return Err(EmbeddingError::Configuration(
                "invalid endpoint host or size",
            ));
        }
        if self.model.is_empty()
            || self.model.len() > 256
            || self.model.chars().any(char::is_control)
        {
            return Err(EmbeddingError::Configuration("invalid model identifier"));
        }
        if self.expected_response_model.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        }) {
            return Err(EmbeddingError::Configuration(
                "invalid expected model identifier",
            ));
        }
        if !(1..=16_384).contains(&self.dimensions) || self.version == 0 {
            return Err(EmbeddingError::Configuration(
                "invalid dimension or version",
            ));
        }
        if !(1..=30).contains(&self.timeout_seconds) || !(1..=64).contains(&self.batch_size) {
            return Err(EmbeddingError::Configuration(
                "invalid timeout or batch size",
            ));
        }
        if self.api_key_env.as_ref().is_some_and(|name| {
            name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }) {
            return Err(EmbeddingError::Configuration(
                "invalid credential environment reference",
            ));
        }
        Ok(())
    }
    fn persistence_id(&self) -> String {
        // A service/model/dimension-control change must not admit stale vectors.
        // Credentials and deadlines do not change the embedding identity.
        let input = format!(
            "{:?}\0{}\0{}\0{:?}\0{}",
            self.protocol,
            self.endpoint,
            self.model,
            self.expected_response_model,
            self.request_dimensions
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, input.as_bytes());
        let suffix = digest.as_ref()[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("http-embedding:{suffix}:{}", self.model)
    }
}
struct Work {
    texts: Vec<String>,
    deadline: Instant,
    result: SyncSender<Result<Vec<Vec<f32>>, EmbeddingError>>,
}
/// Bounded synchronous trait bridge. HTTP client/runtime lives exclusively on
/// its own thread, including destruction, so use/drop inside Tokio cannot panic.
pub struct HttpEmbedder {
    sender: SyncSender<Work>,
    identity: String,
    dimensions: usize,
    version: u32,
    timeout: Duration,
    batch_size: usize,
    requests: Arc<AtomicU64>,
}
impl std::fmt::Debug for HttpEmbedder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpEmbedder")
            .field("identity", &self.identity)
            .field("dimensions", &self.dimensions)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}
impl HttpEmbedder {
    pub fn new(config: HttpEmbeddingConfig) -> Result<Self, EmbeddingError> {
        config.validate()?;
        let key = match &config.api_key_env {
            Some(name) => Some(Zeroizing::new(std::env::var(name).map_err(|_| {
                EmbeddingError::Configuration("configured credential reference is missing")
            })?)),
            None => None,
        };
        if key
            .as_ref()
            .is_some_and(|key| key.is_empty() || key.contains(['\n', '\r']))
        {
            return Err(EmbeddingError::Configuration(
                "configured credential is invalid",
            ));
        }
        Self::with_key(config, key)
    }
    fn with_key(
        config: HttpEmbeddingConfig,
        key: Option<Zeroizing<String>>,
    ) -> Result<Self, EmbeddingError> {
        let identity = config.persistence_id();
        let dimensions = config.dimensions;
        let version = config.version;
        let timeout = Duration::from_secs(config.timeout_seconds);
        let batch_size = config.batch_size;
        let requests = Arc::new(AtomicU64::new(0));
        let worker_requests = Arc::clone(&requests);
        let (sender, receiver) = mpsc::sync_channel::<Work>(1);
        let (ready, started) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("embedding-http".into())
            .spawn(move || {
                let client = match reqwest::blocking::Client::builder()
                    .timeout(timeout)
                    .connect_timeout(timeout)
                    .redirect(reqwest::redirect::Policy::none())
                    .no_proxy()
                    .pool_max_idle_per_host(1)
                    .build()
                {
                    Ok(client) => client,
                    Err(_) => {
                        let _ = ready.send(Err(EmbeddingError::Configuration(
                            "cannot initialize HTTP client",
                        )));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                while let Ok(work) = receiver.recv() {
                    let result = if Instant::now() >= work.deadline {
                        Err(EmbeddingError::Timeout)
                    } else {
                        worker_requests.fetch_add(1, Ordering::Relaxed);
                        request(
                            &client,
                            &config,
                            key.as_ref(),
                            &work.texts,
                            work.deadline.saturating_duration_since(Instant::now()),
                        )
                    };
                    let _ = work.result.send(result);
                }
            })
            .map_err(|_| EmbeddingError::Configuration("cannot start HTTP embedding worker"))?;
        started
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| EmbeddingError::Configuration("HTTP worker did not initialize"))??;
        Ok(Self {
            sender,
            identity,
            dimensions,
            version,
            timeout,
            batch_size,
            requests,
        })
    }
    pub fn request_attempts(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    fn request_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let (result, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + self.timeout;
        let work = Work {
            texts: texts.iter().map(|text| (*text).to_owned()).collect(),
            deadline,
            result,
        };
        self.sender.try_send(work).map_err(|error| match error {
            mpsc::TrySendError::Full(_) => EmbeddingError::Busy,
            mpsc::TrySendError::Disconnected(_) => EmbeddingError::Transport,
        })?;
        receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => EmbeddingError::Timeout,
                mpsc::RecvTimeoutError::Disconnected => EmbeddingError::Transport,
            })?
    }
}
impl Embedder for HttpEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let mut vectors = self.embed_batch(&[text])?;
        Ok(vectors.remove(0))
    }
    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        if texts
            .iter()
            .any(|text| text.trim().is_empty() || text.len() > 8192)
        {
            return Err(EmbeddingError::InvalidInput(
                "texts must be nonempty and at most 8192 UTF-8 bytes",
            ));
        }
        let mut vectors = Vec::with_capacity(texts.len());
        let mut offset = 0;
        while offset < texts.len() {
            let mut end = offset;
            let mut bytes = 0;
            while end < texts.len()
                && end - offset < self.batch_size
                && bytes + texts[end].len() <= MAX_BATCH_BYTES
            {
                bytes += texts[end].len();
                end += 1;
            }
            vectors.extend(self.request_batch(&texts[offset..end])?);
            offset = end;
        }
        Ok(vectors)
    }
    fn dim(&self) -> usize {
        self.dimensions
    }
    fn model_id(&self) -> &str {
        &self.identity
    }
    fn version(&self) -> u32 {
        self.version
    }
    fn is_remote(&self) -> bool {
        true
    }
}
fn request(
    client: &reqwest::blocking::Client,
    config: &HttpEmbeddingConfig,
    key: Option<&Zeroizing<String>>,
    texts: &[String],
    remaining: Duration,
) -> Result<Vec<Vec<f32>>, EmbeddingError> {
    let mut body = json!({"model":config.model,"input":texts});
    match config.protocol {
        HttpEmbeddingProtocol::OpenaiCompatible => body["encoding_format"] = json!("float"),
        HttpEmbeddingProtocol::Ollama => body["truncate"] = json!(false),
    }
    if config.request_dimensions {
        body["dimensions"] = json!(config.dimensions);
    }
    let mut request = client.post(&config.endpoint).timeout(remaining).json(&body);
    if let Some(key) = key {
        request = request.bearer_auth(key.as_str());
    }
    let mut response = request.send().map_err(|error| {
        if error.is_timeout() {
            EmbeddingError::Timeout
        } else {
            EmbeddingError::Transport
        }
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => EmbeddingError::Authentication,
            429 => EmbeddingError::RateLimited,
            status => EmbeddingError::Upstream(status),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(EmbeddingError::InvalidResponse(
            "response exceeds byte limit",
        ));
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| EmbeddingError::Transport)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(EmbeddingError::InvalidResponse(
            "response exceeds byte limit",
        ));
    }
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|_| EmbeddingError::InvalidResponse("invalid JSON"))?;
    if body["model"].as_str()
        != Some(
            config
                .expected_response_model
                .as_deref()
                .unwrap_or(&config.model),
        )
    {
        return Err(EmbeddingError::InvalidResponse("model identity mismatch"));
    }
    match config.protocol {
        HttpEmbeddingProtocol::Ollama => {
            let values = body["embeddings"]
                .as_array()
                .ok_or(EmbeddingError::InvalidResponse("missing vectors"))?;
            if values.len() != texts.len() {
                return Err(EmbeddingError::InvalidResponse("batch count mismatch"));
            }
            values
                .iter()
                .map(|value| decode_vector(value, config.dimensions))
                .collect()
        }
        HttpEmbeddingProtocol::OpenaiCompatible => {
            let values = body["data"]
                .as_array()
                .ok_or(EmbeddingError::InvalidResponse("missing vectors"))?;
            if values.len() != texts.len() {
                return Err(EmbeddingError::InvalidResponse("batch count mismatch"));
            }
            let mut slots = vec![None; texts.len()];
            for value in values {
                let index = value["index"]
                    .as_u64()
                    .and_then(|index| usize::try_from(index).ok())
                    .filter(|index| *index < slots.len())
                    .ok_or(EmbeddingError::InvalidResponse("invalid batch index"))?;
                if slots[index].is_some() {
                    return Err(EmbeddingError::InvalidResponse("duplicate batch index"));
                }
                slots[index] = Some(decode_vector(&value["embedding"], config.dimensions)?);
            }
            slots
                .into_iter()
                .map(|slot| slot.ok_or(EmbeddingError::InvalidResponse("missing batch index")))
                .collect()
        }
    }
}
fn decode_vector(value: &Value, dimension: usize) -> Result<Vec<f32>, EmbeddingError> {
    let values = value
        .as_array()
        .filter(|values| values.len() == dimension)
        .ok_or(EmbeddingError::InvalidResponse("dimension mismatch"))?;
    let vector = values
        .iter()
        .map(|value| {
            value
                .as_f64()
                .filter(|value| value.is_finite())
                .map(|value| value as f32)
                .filter(|value| value.is_finite())
                .ok_or(EmbeddingError::InvalidResponse(
                    "non-finite or nonnumeric vector",
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let norm = vector.iter().fold(0_f32, |sum, value| sum + value * value);
    if !norm.is_finite() || norm <= 0.0 {
        return Err(EmbeddingError::InvalidResponse("invalid vector norm"));
    }
    Ok(vector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContextManager, Fact, FactCategory, SqliteContextManager};
    use std::sync::Arc;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn config(
        server: &MockServer,
        protocol: HttpEmbeddingProtocol,
        dimension: usize,
    ) -> HttpEmbeddingConfig {
        HttpEmbeddingConfig {
            protocol,
            endpoint: format!(
                "{}{}",
                server.uri(),
                if protocol == HttpEmbeddingProtocol::Ollama {
                    "/api/embed"
                } else {
                    "/v1/embeddings"
                }
            ),
            model: "fixture-model".into(),
            dimensions: dimension,
            version: 1,
            request_dimensions: true,
            expected_response_model: None,
            api_key_env: None,
            timeout_seconds: 1,
            batch_size: 32,
        }
    }
    fn fact(content: &str) -> Fact {
        let now = chrono::Utc::now();
        Fact {
            id: uuid::Uuid::new_v4(),
            content: content.into(),
            category: FactCategory::Fact,
            created_at: now,
            last_accessed_at: now,
            embedding: None,
        }
    }
    fn semantic_mock(dimension: usize) -> impl wiremock::Respond {
        move |request: &wiremock::Request| {
            let request: Value = serde_json::from_slice(&request.body).unwrap();
            let inputs = request["input"].as_array().unwrap();
            let data = inputs
                .iter()
                .enumerate()
                .map(|(index, input)| {
                    let text = input.as_str().unwrap();
                    let mut vector = vec![0.; dimension];
                    vector[if text.contains("cobalt") || text.contains("blue") {
                        0
                    } else {
                        1
                    }] = 1.;
                    json!({"index":index,"embedding":vector})
                })
                .collect::<Vec<_>>();
            ResponseTemplate::new(200).set_body_json(json!({"model":"fixture-model","data":data}))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn openai_batch_uses_float_dimensions_and_reorders_indexes() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/v1/embeddings")).and(body_json(json!({"model":"fixture-model","input":["a","b"],"encoding_format":"float","dimensions":3}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"model":"fixture-model","data":[{"index":1,"embedding":[0.,1.,0.]},{"index":0,"embedding":[1.,0.,0.]}]}))).expect(1).mount(&server).await;
        let embedder =
            HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 3)).unwrap();
        assert_eq!(
            embedder.embed_batch(&["a", "b"]).unwrap(),
            vec![vec![1., 0., 0.], vec![0., 1., 0.]]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ollama_disables_silent_truncation_and_validates_dimensions() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/embed"))
            .and(body_json(
                json!({"model":"fixture-model","input":["a"],"truncate":false,"dimensions":2}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"model":"fixture-model","embeddings":[[0.2,0.7]]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let embedder =
            HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::Ollama, 2)).unwrap();
        assert_eq!(embedder.embed("a").unwrap(), vec![0.2, 0.7]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn upstream_failures_are_typed_and_never_reflect_bodies_or_credentials() {
        for (status, expected) in [
            (401, EmbeddingError::Authentication),
            (429, EmbeddingError::RateLimited),
            (500, EmbeddingError::Upstream(500)),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_string("credential=fixture-secret private prompt text"),
                )
                .expect(1)
                .mount(&server)
                .await;
            let embedder = HttpEmbedder::with_key(
                config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 2),
                Some(Zeroizing::new("fixture-secret".into())),
            )
            .unwrap();
            let error = embedder.embed("private prompt text").unwrap_err();
            assert_eq!(error, expected);
            assert!(!format!("{error:?}").contains("fixture-secret"));
            assert!(!format!("{embedder:?}").contains("fixture-secret"));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn malformed_model_vector_and_batch_replies_fail_closed() {
        for body in [
            json!({"model":"wrong","data":[{"index":0,"embedding":[1.,0.]}]}),
            json!({"model":"fixture-model","data":[{"index":0,"embedding":[0.,0.]}]}),
            json!({"model":"fixture-model","data":[{"index":0,"embedding":[1.]}]}),
            json!({"model":"fixture-model","data":[{"index":1,"embedding":[1.,0.]}]}),
            json!({"model":"fixture-model","data":[]}),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
            let embedder =
                HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 2))
                    .unwrap();
            assert!(matches!(
                embedder.embed("input"),
                Err(EmbeddingError::InvalidResponse(_))
            ));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timeout_and_redirect_do_not_store_a_fact_or_forward_a_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&server)
            .await;
        let embedder =
            HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 2)).unwrap();
        assert_eq!(
            embedder.embed("input").unwrap_err(),
            EmbeddingError::Timeout
        );
        let redirect = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("location", format!("{}/v1/embeddings", destination.uri())),
            )
            .mount(&redirect)
            .await;
        let embedder = HttpEmbedder::with_key(
            config(&redirect, HttpEmbeddingProtocol::OpenaiCompatible, 2),
            Some(Zeroizing::new("fixture-secret".into())),
        )
        .unwrap();
        assert_eq!(
            embedder.embed("input").unwrap_err(),
            EmbeddingError::Upstream(307)
        );
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kernel_fact_paths_migrate_models_and_dimension_changes_atomically() {
        let first = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(semantic_mock(3))
            .mount(&first)
            .await;
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let foreign = uuid::Uuid::new_v4();
        let blue = fact("cobalt preference");
        let purple = fact("purple preference");
        manager.store_fact(owner, blue.clone()).await.unwrap();
        manager.store_fact(owner, purple).await.unwrap();
        let embedder = Arc::new(
            HttpEmbedder::new(config(&first, HttpEmbeddingProtocol::OpenaiCompatible, 3)).unwrap(),
        );
        let identity = embedder.model_id().to_owned();
        let manager = manager.with_embedder(embedder);
        let result = manager.query_memory(owner, "blue").await.unwrap();
        assert_eq!(result[0].id, blue.id);
        assert_eq!(result[0].embedding.as_ref().unwrap().len(), 3);
        assert!(manager
            .query_memory(foreign, "blue")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            manager
                .locked_conn()
                .query_row(
                    "SELECT embedding_model FROM facts WHERE id=?1",
                    [blue.id.to_string()],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            identity
        );
        let second = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(semantic_mock(5))
            .mount(&second)
            .await;
        let mut changed = config(&second, HttpEmbeddingProtocol::OpenaiCompatible, 5);
        changed.version = 2;
        let manager = manager.with_embedder(Arc::new(HttpEmbedder::new(changed).unwrap()));
        assert_eq!(manager.reindex_memory(owner).unwrap(), 2);
        let result = manager.query_memory(owner, "blue").await.unwrap();
        assert_eq!(result[0].id, blue.id);
        assert!(result
            .iter()
            .all(|fact| fact.embedding.as_ref().unwrap().len() == 5));
        manager.erase_agent_data(owner).unwrap();
        assert!(manager
            .query_memory(owner, "blue")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_service_calls_leave_new_and_existing_vectors_unchanged() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let stored = fact("old model content");
        manager.store_fact(owner, stored.clone()).await.unwrap();
        let original = manager
            .locked_conn()
            .query_row(
                "SELECT embedding_blob FROM facts WHERE id=?1",
                [stored.id.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap();
        let manager = manager.with_embedder(Arc::new(
            HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 2)).unwrap(),
        ));
        assert!(matches!(
            manager.store_fact(owner, fact("new fact")).await,
            Err(crate::ContextError::Embedding(EmbeddingError::Upstream(
                500
            )))
        ));
        assert!(manager.query_memory(owner, "query").await.is_err());
        assert!(manager.reindex_memory(owner).is_err());
        let conn = manager.locked_conn();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM facts", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            conn.query_row(
                "SELECT embedding_blob FROM facts WHERE id=?1",
                [stored.id.to_string()],
                |row| row.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
            original
        );
    }

    #[test]
    fn unsafe_configuration_and_inputs_are_rejected_without_io() {
        for endpoint in [
            "http://example.com/v1/embeddings",
            "https://user:secret@example.com/embeddings",
            "https://example.com/embeddings?api_key=secret",
            "file:///tmp/model",
        ] {
            let config = HttpEmbeddingConfig {
                protocol: HttpEmbeddingProtocol::OpenaiCompatible,
                endpoint: endpoint.into(),
                model: "fixture".into(),
                dimensions: 2,
                version: 1,
                request_dimensions: false,
                expected_response_model: None,
                api_key_env: None,
                timeout_seconds: 1,
                batch_size: 32,
            };
            assert!(config.validate().is_err());
        }
        assert!(matches!(
            decode_vector(&json!([1e300, 0]), 2),
            Err(EmbeddingError::InvalidResponse(_))
        ));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn normal_kernel_boot_selects_configured_backend_but_is_lazy() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(semantic_mock(3))
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let mut settings = crate::config::Config {
            data_dir: directory.path().join("configured"),
            ..Default::default()
        };
        assert!(settings.embeddings.is_none());
        settings.embeddings = Some(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 3));
        let kernel = crate::AgentKernelImpl::from_config(&settings).unwrap();
        assert!(server.received_requests().await.unwrap().is_empty());
        let owner = uuid::Uuid::new_v4();
        let stored = fact("cobalt preference");
        kernel
            .context_manager
            .store_fact(owner, stored.clone())
            .await
            .unwrap();
        let result = kernel
            .context_manager
            .query_memory(owner, "blue")
            .await
            .unwrap();
        assert_eq!(result[0].id, stored.id);
        assert_eq!(result[0].embedding.as_ref().unwrap().len(), 3);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        let mut invalid = settings.clone();
        invalid.data_dir = directory.path().join("invalid");
        invalid.embeddings.as_mut().unwrap().dimensions = 0;
        assert!(crate::AgentKernelImpl::from_config(&invalid).is_err());
        assert!(!invalid.data_dir.join("agent_os.db").exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_batch_failure_rolls_back_model_repair_for_every_fact() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(body_json(json!({"model":"fixture-model","input":["cobalt first"],"encoding_format":"float","dimensions":2}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"model":"fixture-model","data":[{"index":0,"embedding":[1.,0.]}]}))).mount(&server).await;
        Mock::given(method("POST")).and(body_json(json!({"model":"fixture-model","input":["purple second"],"encoding_format":"float","dimensions":2}))).respond_with(ResponseTemplate::new(503)).mount(&server).await;
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        manager
            .store_fact(owner, fact("cobalt first"))
            .await
            .unwrap();
        manager
            .store_fact(owner, fact("purple second"))
            .await
            .unwrap();
        let mut settings = config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 2);
        settings.batch_size = 1;
        let manager = manager.with_embedder(Arc::new(HttpEmbedder::new(settings).unwrap()));
        assert!(manager.reindex_memory(owner).is_err());
        assert_eq!(manager.locked_conn().query_row("SELECT COUNT(*) FROM facts WHERE embedding_model='blended-feature-hash' AND embedding_dim=256",[],|row|row.get::<_,i64>(0)).unwrap(),2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remote_backend_keeps_tenant_checks_and_purge_unchanged() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(semantic_mock(3))
            .mount(&server)
            .await;
        let manager = SqliteContextManager::in_memory()
            .unwrap()
            .with_embedder(Arc::new(
                HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 3))
                    .unwrap(),
            ));
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        for (owner, tenant, text) in [
            (first, "tenant-a", "cobalt one"),
            (second, "tenant-b", "purple two"),
        ] {
            let now = chrono::Utc::now();
            manager
                .save_agent(&crate::context::PersistedAgent {
                    id: owner,
                    session_id: uuid::Uuid::new_v4(),
                    tenant_id: tenant.into(),
                    name: "embedding fixture".into(),
                    task: "test".into(),
                    llm_provider: "offline".into(),
                    permission_profile: "standard".into(),
                    priority: 3,
                    status: "\"Running\"".into(),
                    sandbox_config_json: None,
                    created_at: now,
                    last_activity_at: now,
                })
                .unwrap();
            manager.store_fact(owner, fact(text)).await.unwrap();
        }
        let before = server.received_requests().await.unwrap().len();
        assert!(manager
            .query_memory_for_tenant("tenant-b", first, "blue")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), before);
        manager
            .query_memory_for_tenant("tenant-a", first, "blue")
            .await
            .unwrap();
        manager.erase_tenant_data("tenant-a").unwrap();
        assert!(manager
            .query_memory(first, "blue")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            manager
                .query_memory_for_tenant("tenant-b", second, "purple")
                .await
                .unwrap()[0]
                .content,
            "purple two"
        );
    }
    #[tokio::test]
    async fn cold_remote_repair_works_on_single_thread_tokio_without_holding_the_connection() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(semantic_mock(3))
            .mount(&server)
            .await;
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        manager
            .store_fact(owner, fact("cobalt old embedding"))
            .await
            .unwrap();
        let manager = manager.with_embedder(Arc::new(
            HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 3)).unwrap(),
        ));
        let result = manager.query_memory(owner, "blue").await.unwrap();
        assert_eq!(result[0].embedding.as_ref().unwrap().len(), 3);
    }
    #[tokio::test]
    async fn changed_store_revision_rejects_stale_remote_vectors() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(body_json(json!({"model":"fixture-model","input":["blue"],"encoding_format":"float","dimensions":3}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"model":"fixture-model","data":[{"index":0,"embedding":[1.,0.,0.]}]}))).mount(&server).await;
        Mock::given(method("POST")).and(body_json(json!({"model":"fixture-model","input":["cobalt old"],"encoding_format":"float","dimensions":3}))).respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(100)).set_body_json(json!({"model":"fixture-model","data":[{"index":0,"embedding":[1.,0.,0.]}]}))).mount(&server).await;
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let stored = fact("cobalt old");
        manager.store_fact(owner, stored.clone()).await.unwrap();
        let manager = Arc::new(manager.with_embedder(Arc::new(
            HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 3)).unwrap(),
        )));
        let query = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.query_memory(owner, "blue").await }
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while server.received_requests().await.unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        manager
            .locked_conn()
            .execute(
                "UPDATE facts SET content='newer owned content' WHERE id=?1",
                [stored.id.to_string()],
            )
            .unwrap();
        assert!(matches!(
            query.await.unwrap(),
            Err(crate::ContextError::Embedding(EmbeddingError::StoreChanged))
        ));
        let row = manager
            .locked_conn()
            .query_row(
                "SELECT content,embedding_model FROM facts WHERE id=?1",
                [stored.id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        assert_eq!(row.0, "newer owned content");
        assert_eq!(row.1, "blended-feature-hash");
    }

    #[tokio::test]
    async fn cancelling_remote_repair_does_not_write_from_the_worker() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(body_json(json!({"model":"fixture-model","input":["blue"],"encoding_format":"float","dimensions":3}))).respond_with(ResponseTemplate::new(200).set_body_json(json!({"model":"fixture-model","data":[{"index":0,"embedding":[1.,0.,0.]}]}))).mount(&server).await;
        Mock::given(method("POST")).and(body_json(json!({"model":"fixture-model","input":["cobalt old"],"encoding_format":"float","dimensions":3}))).respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(100)).set_body_json(json!({"model":"fixture-model","data":[{"index":0,"embedding":[1.,0.,0.]}]}))).mount(&server).await;
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        manager.store_fact(owner, fact("cobalt old")).await.unwrap();
        let manager = Arc::new(manager.with_embedder(Arc::new(
            HttpEmbedder::new(config(&server, HttpEmbeddingProtocol::OpenaiCompatible, 3)).unwrap(),
        )));
        let query = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.query_memory(owner, "blue").await }
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while server.received_requests().await.unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        query.abort();
        assert!(query.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            manager
                .locked_conn()
                .query_row(
                    "SELECT embedding_model FROM facts WHERE agent_id=?1",
                    [owner.to_string()],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "blended-feature-hash"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dimension_expansion_respects_limits_and_preserves_old_vectors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(semantic_mock(400))
            .mount(&server)
            .await;
        let manager = SqliteContextManager::in_memory().unwrap();
        let owner = uuid::Uuid::new_v4();
        let stored = fact("cobalt");
        manager.store_fact(owner, stored.clone()).await.unwrap();
        manager
            .set_context_storage_limits(crate::context::ContextStorageLimits {
                per_agent_bytes: 1040,
                per_tenant_bytes: 1040,
                global_bytes: 1040,
                spill_retention_seconds: 60,
            })
            .unwrap();
        let original = manager
            .locked_conn()
            .query_row(
                "SELECT embedding_blob FROM facts WHERE id=?1",
                [stored.id.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap();
        let manager = manager.with_embedder(Arc::new(
            HttpEmbedder::new(config(
                &server,
                HttpEmbeddingProtocol::OpenaiCompatible,
                400,
            ))
            .unwrap(),
        ));
        assert!(matches!(
            manager.reindex_memory(owner),
            Err(crate::ContextError::PersistenceFailed(_))
        ));
        assert!(matches!(
            manager.query_memory(owner, "blue").await,
            Err(crate::ContextError::PersistenceFailed(_))
        ));
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "byte admission must happen before remote requests"
        );
        let row = manager
            .locked_conn()
            .query_row(
                "SELECT embedding_model,embedding_dim,embedding_blob FROM facts WHERE id=?1",
                [stored.id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, "blended-feature-hash");
        assert_eq!(row.1, 256);
        assert_eq!(row.2, original);
    }
}
