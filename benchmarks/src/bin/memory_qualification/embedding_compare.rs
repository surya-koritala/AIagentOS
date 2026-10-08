//! Opt-in semantic quality comparison over one fixed labelled corpus.

use kernel::memory_manager::{
    BlendedEmbedder, BruteForceIndex, Embedder, HttpEmbedder, HttpEmbeddingConfig, VectorIndex,
};
use serde_json::{json, Value};
use std::io::Read;
use std::path::Path;
use std::time::Instant;

const THEMES: [(&str,[&str;2]);10] = [
    ("Verified backup archives recover persisted state after storage failures.",["The disk broke; how can I get my saved work back?","Restore the last recovery point after losing a machine."]),
    ("Capability and mandatory access policies authorize resources and reject forbidden actions.",["Stop an untrusted worker changing protected files.","Only approved privileges should allow an action."]),
    ("Transient HTTP rate limits use bounded retries with backoff and typed provider errors.",["The model service is busy; wait before sending another request.","Handle a temporarily overloaded inference endpoint."]),
    ("Token and spending quotas reserve usage and prevent budget exhaustion.",["Keep the API bill under my allowance.","Do not let a task consume more tokens than permitted."]),
    ("Paused agents continue from durable generation checkpoints without repeating completed work.",["Resume a stopped job from its saved position.","Continue after interruption instead of starting over."]),
    ("Publisher signatures and trusted digests authenticate installed package artifacts.",["Check a downloaded extension is genuine before loading it.","Verify that the add-on came from an approved signer."]),
    ("Tenant namespaces isolate owned data, credentials, and resources from other tenants.",["Keep one customer's confidential records away from another.","Separate the documents and secrets of different accounts."]),
    ("Workspace path confinement rejects symlinks and prevents directory traversal escapes.",["A file link must not reach outside the project folder.","Block paths that jump above the allowed working directory."]),
    ("Broker mailboxes deliver owned messages between cooperating agents.",["Send another worker a progress update.","Let two jobs exchange a note through their inboxes."]),
    ("Versioned database migrations preserve supported schemas and reject newer incompatible readers.",["The old executable must refuse a store from a future release.","Upgrade saved data without losing state when the format changes."]),
];

fn corpus() -> (Vec<String>, Vec<(usize, String)>) {
    let documents=THEMES.iter().enumerate().flat_map(|(topic,(description,_))|(0..10).map(move|instance|format!("Reference {topic}-{instance}: {description} Example operation {instance} retains its checked outcome."))).collect();
    let queries = THEMES
        .iter()
        .enumerate()
        .flat_map(|(topic, (_, queries))| {
            queries
                .iter()
                .map(move |query| (topic, (*query).to_owned()))
        })
        .collect();
    (documents, queries)
}
fn evaluate(
    embedder: &dyn Embedder,
    documents: &[String],
    queries: &[(usize, String)],
) -> Result<Value, String> {
    let tick = Instant::now();
    let refs = documents.iter().map(String::as_str).collect::<Vec<_>>();
    let vectors = embedder
        .embed_batch(&refs)
        .map_err(|error| error.to_string())?;
    if vectors.len() != documents.len()
        || vectors.iter().any(|vector| {
            vector.len() != embedder.dim() || vector.iter().any(|value| !value.is_finite())
        })
    {
        return Err("embedding batch contract mismatch".into());
    }
    let mut index = BruteForceIndex::new();
    for (id, vector) in vectors.into_iter().enumerate() {
        index.add(id as u64, vector);
    }
    let query_refs = queries
        .iter()
        .map(|(_, query)| query.as_str())
        .collect::<Vec<_>>();
    let query_vectors = embedder
        .embed_batch(&query_refs)
        .map_err(|error| error.to_string())?;
    if query_vectors.len() != queries.len() {
        return Err("query embedding batch count mismatch".into());
    }
    let mut recall = 0_f64;
    let mut top1 = 0usize;
    let mut rows = Vec::new();
    for ((topic, query), vector) in queries.iter().zip(query_vectors) {
        if vector.len() != embedder.dim() || vector.iter().any(|value| !value.is_finite()) {
            return Err("query vector contract mismatch".into());
        }
        let hits = index.search(&vector, 10);
        let matched = hits
            .iter()
            .filter(|(id, _)| *id as usize / 10 == *topic)
            .count();
        let first = hits
            .first()
            .is_some_and(|(id, _)| *id as usize / 10 == *topic);
        recall += matched as f64 / 10.;
        top1 += usize::from(first);
        rows.push(json!({"query":query,"expected_topic":topic,"recall_at_10":matched as f64/10.,"top1_relevant":first,"returned_document_ids":hits.iter().map(|(id,_)|*id).collect::<Vec<_>>()}));
    }
    Ok(
        json!({"model_id":embedder.model_id(),"version":embedder.version(),"dimensions":embedder.dim(),"recall_at_10":recall/queries.len() as f64,"top1_relevance":top1 as f64/queries.len() as f64,"elapsed_ms":tick.elapsed().as_millis(),"queries":rows}),
    )
}
pub(super) fn run(path: &Path) -> Result<(), String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "cannot read embedding comparison configuration")?
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read embedding comparison configuration")?;
    if bytes.len() > 8192 {
        return Err("embedding comparison configuration exceeds byte limit".into());
    }
    let config: HttpEmbeddingConfig =
        serde_json::from_slice(&bytes).map_err(|_| "invalid embedding comparison configuration")?;
    let backend = HttpEmbedder::new(config).map_err(|error| error.to_string())?;
    let (documents, queries) = corpus();
    let offline = evaluate(&BlendedEmbedder::default(), &documents, &queries)?;
    let http = evaluate(&backend, &documents, &queries);
    let (http, error) = match http {
        Ok(value) => (value, None),
        Err(error) => (Value::Null, Some(error)),
    };
    let report = json!({"schema_version":1,"mode":"embedding-semantic-comparison","evidence_class":"fixed-labelled-corpus","production_claim_allowed":false,"document_count":documents.len(),"query_count":queries.len(),"top_k":10,"ground_truth":"each query is labelled with one topic's ten documents","offline":offline,"http":http,"http_request_attempts":backend.request_attempts(),"http_error":error,"billing_cost_usd":null,"passed":error.is_none()});
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|_| "cannot serialize embedding comparison")?
    );
    if error.is_some() {
        return Err("HTTP comparison did not complete; no quality claim is available".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn labelled_corpus_has_independent_ground_truth_and_reports_offline_quality() {
        let (documents, queries) = corpus();
        assert_eq!(documents.len(), 100);
        assert_eq!(queries.len(), 20);
        let report = evaluate(&BlendedEmbedder::default(), &documents, &queries).unwrap();
        assert_eq!(report["queries"].as_array().unwrap().len(), 20);
        assert!((0.0..=1.0).contains(&report["recall_at_10"].as_f64().unwrap()));
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn comparison_reports_both_embedders_without_assuming_real_model_quality() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let (documents, queries) = corpus();
        let mut labelled = std::collections::HashMap::new();
        for (id, text) in documents.iter().enumerate() {
            labelled.insert(text.clone(), id / 10);
        }
        for (topic, text) in &queries {
            labelled.insert(text.clone(), *topic);
        }
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let data = body["input"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .map(|(index, input)| {
                        let mut vector = vec![0.; 10];
                        vector[labelled[input.as_str().unwrap()]] = 1.;
                        json!({"index":index,"embedding":vector})
                    })
                    .collect::<Vec<_>>();
                ResponseTemplate::new(200).set_body_json(json!({"model":"fixture","data":data}))
            })
            .mount(&server)
            .await;
        let config = HttpEmbeddingConfig {
            protocol: kernel::memory_manager::HttpEmbeddingProtocol::OpenaiCompatible,
            endpoint: format!("{}/v1/embeddings", server.uri()),
            model: "fixture".into(),
            dimensions: 10,
            version: 1,
            request_dimensions: false,
            expected_response_model: None,
            api_key_env: None,
            timeout_seconds: 1,
            batch_size: 32,
        };
        let http = HttpEmbedder::new(config).unwrap();
        let report = evaluate(&http, &documents, &queries).unwrap();
        assert_eq!(report["recall_at_10"], 1.0);
        assert_eq!(report["top1_relevance"], 1.0);
        assert_eq!(http.request_attempts(), 5);
        let offline = evaluate(&BlendedEmbedder::default(), &documents, &queries).unwrap();
        assert_eq!(offline["model_id"], "blended-feature-hash");
    }
}
