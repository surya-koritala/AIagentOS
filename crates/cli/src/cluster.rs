//! Kernel-backed cluster administration; no alternate local executor.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agent_sdk::{
    AgentMutationFenceProof, AuthorityCommand, AuthorityResponse, ClusterAdmissionOperationIds, ClusterClient, ClusterMemberState,
    ConnectionProfile, ConnectionTransport, NodeAvailability, NodeProfile, SdkError,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::OperatorClient;

#[path = "cluster_principal.rs"]
mod principal;
use principal::{PrincipalOptions, PrincipalSigner};

pub const USAGE: &str = "Usage: agentctl [SERVER OPTIONS] cluster COMMAND [OPTIONS]
  node-availability <active|draining|quarantined> <reason> --generation N
  node-profile <json> --generation N --reason R
  join --authority ADDR --node ADDR [--generation N] --reason R
  members
  member-state NODE_ID <active|left|revoked> <reason> --generation N
  cert-prepare --authority ADDR --node ADDR --candidate-fingerprint SHA256 --generation N --reason R
               [--prepare-ttl SECONDS] [--minimum-overlap SECONDS]
  cert-activate --authority ADDR --node ADDR --generation N --reason R
  cert-abort NODE_ID --generation N --reason R
  cert-finalize NODE_ID --generation N --reason R
  ownerships [--after AGENT_ID] [--limit N]
  fence-install AGENT_ID <proof-json> --reason R
  fence-retire AGENT_ID <proof-json> --reason R
  fence-show AGENT_ID

Every write accepts --operation-id UUID and prints the id used.
Join/cert-prepare/cert-activate also accept --challenge-operation-id UUID.
Without an explicit challenge id, it is deterministically derived from the mutation id.
Two-endpoint operations accept --node-token TOKEN, --node-ca PATH and --node-server-name NAME.
The authority uses the common AGENTOS_TLS_CA/AGENTOS_TLS_SERVER_NAME profile.
The node inherits that secure profile unless its own verified TLS profile is supplied.
Replicated membership writes require --principal-id UUID --principal-generation N
and --principal-key PATH to a bounded owner-only Ed25519 PKCS#8 DER file.
The principal key signs on this client; API credentials and node keys cannot replace it.
Certificate activation connects to the candidate leaf and re-admits the exact member generation.
Draining rejects new work; it does not report completed migration or safe-to-stop status.

Tracked commands unavailable until their kernel dependencies exist (nonzero exit):
  reconfigure-voters / reconfigure-trust / reconfiguration-status: #306
  drain-node / upgrade-node / remove-node: #314 (depends on #306 and #310)
  migrate-agent: #310
Pending operation receipts require reconciliation; they never trigger automatic re-execution.";

pub struct Command {
    action: Action,
    operation_id: Option<Uuid>,
    principal: Option<PrincipalOptions>,
}

enum Action {
    Unavailable(&'static str),
    Members,
    Ownerships {
        after: Option<String>,
        limit: usize,
    },
    FenceShow(String),
    Availability {
        availability: NodeAvailability,
        generation: u64,
        reason: String,
    },
    Profile {
        profile: NodeProfile,
        generation: u64,
        reason: String,
    },
    Join(Join),
    CertificatePrepare {
        join: Join,
        fingerprint: String,
        ttl: u64,
        overlap: u64,
    },
    MemberState {
        node_id: String,
        state: ClusterMemberState,
        generation: u64,
        reason: String,
    },
    CertificateFinish {
        node_id: String,
        abort: bool,
        generation: u64,
        reason: String,
    },
    Fence {
        agent_id: String,
        proof: AgentMutationFenceProof,
        retire: bool,
        reason: String,
    },
}

struct Join {
    authority: String,
    node: String,
    generation: Option<u64>,
    reason: String,
    ids: ClusterAdmissionOperationIds,
    node_token: Option<String>,
    node_ca: Option<PathBuf>,
    node_server_name: Option<String>,
}

#[derive(Default)]
struct Arguments {
    positional: Vec<String>,
    options: BTreeMap<String, String>,
}

impl Arguments {
    fn required(&mut self, name: &str) -> Result<String, String> {
        self.options
            .remove(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing {name}"))
    }

    fn number(&mut self, name: &str) -> Result<u64, String> {
        self.required(name)?
            .parse()
            .map_err(|_| format!("invalid {name}: expected an unsigned integer"))
    }

    fn positional(&self, count: usize) -> Result<(), String> {
        if self.positional.len() == count {
            Ok(())
        } else {
            Err(format!("expected {count} positional arguments"))
        }
    }

    fn finish(self) -> Result<(), String> {
        if let Some((name, _)) = self.options.first_key_value() {
            Err(format!("unrecognized cluster option {name}"))
        } else {
            Ok(())
        }
    }
}

fn uuid(raw: &str) -> Result<Uuid, String> {
    Uuid::parse_str(raw).map_err(|_| "invalid operation UUID".into())
}

fn join(
    arguments: &mut Arguments,
    mutation: Uuid,
    require_generation: bool,
) -> Result<Join, String> {
    arguments.positional(0)?;
    let generation = arguments
        .options
        .remove("--generation")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "invalid --generation".to_string())
        })
        .transpose()?;
    if require_generation && generation.is_none() {
        return Err("missing --generation".into());
    }
    let challenge = if let Some(raw) = arguments.options.remove("--challenge-operation-id") {
        uuid(&raw)?
    } else {
        let mut material = b"AIagentOS cluster CLI challenge operation v1".to_vec();
        material.extend_from_slice(mutation.as_bytes());
        let digest = ring::digest::digest(&ring::digest::SHA256, &material);
        Uuid::from_slice(&digest.as_ref()[..16])
            .map_err(|_| "invalid derived challenge UUID".to_string())?
    };
    if challenge == mutation {
        return Err("challenge and mutation operation UUIDs must differ".into());
    }
    let node_ca = arguments.options.remove("--node-ca").map(PathBuf::from);
    let node_server_name = arguments.options.remove("--node-server-name");
    if node_ca.is_some()
        && node_server_name
            .as_ref()
            .is_none_or(|name| name.trim().is_empty())
    {
        return Err("--node-ca requires --node-server-name".into());
    }
    Ok(Join {
        authority: arguments.required("--authority")?,
        node: arguments.required("--node")?,
        generation,
        reason: arguments.required("--reason")?,
        ids: ClusterAdmissionOperationIds {
            challenge,
            mutation,
        },
        node_token: arguments.options.remove("--node-token"),
        node_ca,
        node_server_name,
    })
}

pub fn parse(values: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut values = values.into_iter();
    let name = values
        .next()
        .ok_or_else(|| "missing cluster command".to_string())?;
    let unavailable = match name.as_str() {
        "reconfigure-voters" | "reconfigure-trust" | "reconfiguration-status" => Some(
            "cluster live reconfiguration is unavailable; backend dependency #306 remains open",
        ),
        "drain-node" | "upgrade-node" | "remove-node" => {
            Some("cluster rolling operations are unavailable; backend #314 requires #306 and #310")
        }
        "migrate-agent" => {
            Some("cluster migration is unavailable; backend dependency #310 remains open")
        }
        _ => None,
    };
    if let Some(message) = unavailable {
        return Ok(Command {
            action: Action::Unavailable(message),
            operation_id: None,
            principal: None,
        });
    }
    let mut arguments = Arguments::default();
    while let Some(value) = values.next() {
        if value.starts_with("--") {
            let next = values
                .next()
                .ok_or_else(|| format!("missing value for {value}"))?;
            if arguments.options.insert(value.clone(), next).is_some() {
                return Err(format!("duplicate cluster option {value}"));
            }
        } else {
            arguments.positional.push(value);
        }
    }
    let writing = matches!(
        name.as_str(),
        "node-availability"
            | "node-profile"
            | "join"
            | "member-state"
            | "cert-prepare"
            | "cert-activate"
            | "cert-abort"
            | "cert-finalize"
            | "fence-install"
            | "fence-retire"
    );
    let operation_id = if writing {
        Some(
            arguments
                .options
                .remove("--operation-id")
                .map(|value| uuid(&value))
                .transpose()?
                .unwrap_or_else(Uuid::new_v4),
        )
    } else {
        None
    };
    let principal = PrincipalOptions::parse(&mut arguments.options)?;
    if principal.is_some() && !matches!(name.as_str(), "join" | "cert-activate" | "cert-prepare" | "cert-abort" | "cert-finalize" | "member-state") {
        return Err("principal signing options require a replicated membership mutation".into());
    }
    let action = match name.as_str() {
        "members" => {
            arguments.positional(0)?;
            Action::Members
        }
        "ownerships" => {
            arguments.positional(0)?;
            let after = arguments.options.remove("--after");
            let limit = arguments
                .options
                .remove("--limit")
                .map(|value| {
                    value
                        .parse::<usize>()
                        .map_err(|_| "invalid --limit".to_string())
                })
                .transpose()?
                .unwrap_or(100);
            if !(1..=1000).contains(&limit) {
                return Err("--limit must be between 1 and 1000".into());
            }
            Action::Ownerships { after, limit }
        }
        "fence-show" => {
            arguments.positional(1)?;
            Action::FenceShow(arguments.positional[0].clone())
        }
        "node-availability" => {
            arguments.positional(2)?;
            let availability = match arguments.positional[0].as_str() {
                "active" => NodeAvailability::Active,
                "draining" => NodeAvailability::Draining,
                "quarantined" => NodeAvailability::Quarantined,
                _ => return Err("invalid node availability".into()),
            };
            Action::Availability {
                availability,
                generation: arguments.number("--generation")?,
                reason: arguments.positional[1].clone(),
            }
        }
        "node-profile" => {
            arguments.positional(1)?;
            let profile = serde_json::from_str(&arguments.positional[0])
                .map_err(|_| "invalid node profile JSON".to_string())?;
            Action::Profile {
                profile,
                generation: arguments.number("--generation")?,
                reason: arguments.required("--reason")?,
            }
        }
        "join" | "cert-activate" => Action::Join(join(
            &mut arguments,
            operation_id.expect("write command has an operation UUID"),
            name == "cert-activate",
        )?),
        "cert-prepare" => {
            let fingerprint = arguments.required("--candidate-fingerprint")?;
            if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("candidate fingerprint must contain 64 hexadecimal characters".into());
            }
            let ttl = arguments
                .options
                .remove("--prepare-ttl")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|_| "invalid --prepare-ttl".to_string())
                })
                .transpose()?
                .unwrap_or(60);
            let overlap = arguments
                .options
                .remove("--minimum-overlap")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|_| "invalid --minimum-overlap".to_string())
                })
                .transpose()?
                .unwrap_or(5);
            Action::CertificatePrepare {
                join: join(
                    &mut arguments,
                    operation_id.expect("write command has an operation UUID"),
                    true,
                )?,
                fingerprint: fingerprint.to_lowercase(),
                ttl,
                overlap,
            }
        }
        "member-state" => {
            arguments.positional(3)?;
            let state = match arguments.positional[1].as_str() {
                "active" => ClusterMemberState::Active,
                "left" => ClusterMemberState::Left,
                "revoked" => ClusterMemberState::Revoked,
                _ => return Err("invalid cluster member state".into()),
            };
            Action::MemberState {
                node_id: arguments.positional[0].clone(),
                state,
                generation: arguments.number("--generation")?,
                reason: arguments.positional[2].clone(),
            }
        }
        "cert-abort" | "cert-finalize" => {
            arguments.positional(1)?;
            Action::CertificateFinish {
                node_id: arguments.positional[0].clone(),
                abort: name == "cert-abort",
                generation: arguments.number("--generation")?,
                reason: arguments.required("--reason")?,
            }
        }
        "fence-install" | "fence-retire" => {
            arguments.positional(2)?;
            let proof = serde_json::from_str(&arguments.positional[1])
                .map_err(|_| "invalid destination fence proof JSON".to_string())?;
            Action::Fence {
                agent_id: arguments.positional[0].clone(),
                proof,
                retire: name == "fence-retire",
                reason: arguments.required("--reason")?,
            }
        }
        _ => return Err("unrecognized cluster command".into()),
    };
    arguments.finish()?;
    Ok(Command {
        action,
        operation_id,
        principal,
    })
}

impl Command {
    pub fn attempt_ids(&self) -> Option<Value> {
        self.operation_id.map(|id| match &self.action {
            Action::Join(join) | Action::CertificatePrepare { join, .. } => {
                json!({"attempt_operation_id": id, "challenge_operation_id": join.ids.challenge})
            }
            _ => json!({"attempt_operation_id": id}),
        })
    }
}

fn json_value(record: &impl serde::Serialize) -> Result<Value, SdkError> {
    serde_json::to_value(record)
        .map_err(|_| SdkError::Kernel("failed to serialize cluster record".into()))
}

async fn node_client(
    join: &Join,
    authority_profile: &ConnectionProfile,
    token: Option<&str>,
) -> Result<OperatorClient, SdkError> {
    let mut profile = authority_profile.clone();
    profile.address = join.node.clone();
    if let Some(ca) = &join.node_ca {
        profile.transport = ConnectionTransport::Tls {
            ca_certificates: ca.clone(),
            server_name: join
                .node_server_name
                .clone()
                .expect("node CA requires a server name"),
        };
    } else if let Some(name) = &join.node_server_name {
        match &mut profile.transport {
            ConnectionTransport::Tls { server_name, .. } => *server_name = name.clone(),
            ConnectionTransport::Plaintext => {
                return Err(SdkError::Configuration(
                    "--node-server-name requires a verified TLS CA profile".into(),
                ))
            }
        }
    }
    OperatorClient::connect_profile(&profile, join.node_token.as_deref().or(token)).await
}

pub async fn run(
    command: Command,
    mut profile: ConnectionProfile,
    token: Option<&str>,
) -> Result<Value, SdkError> {
    if let Action::Unavailable(message) = command.action {
        return Err(SdkError::Configuration(message.into()));
    }
    if let Action::Join(join) | Action::CertificatePrepare { join, .. } = &command.action {
        profile.address = join.authority.clone();
    }
    // Read and validate the explicitly supplied caller key before any I/O to
    // a server. No key is inferred from API credentials or node identity.
    let mut signer = command.principal.map(PrincipalSigner::load).transpose()?;
    let mut client = OperatorClient::connect_profile(&profile, token).await?;
    if command.operation_id.is_some()
        && !client
            .hello()
            .await?
            .features
            .iter()
            .any(|feature| feature == "cluster-operation-receipts-v1")
    {
        return Err(SdkError::Configuration("cluster writes require server feature cluster-operation-receipts-v1; refusing ignored operation IDs".into()));
    }
    let id = command.operation_id.map(|id| id.to_string());
    let record = match command.action {
        Action::Members => json_value(&client.cluster_membership().await?)?,
        Action::Ownerships { after, limit } => {
            json_value(&client.cluster_agent_ownerships(after, limit).await?)?
        }
        Action::FenceShow(agent_id) => json_value(&client.agent_mutation_fence(agent_id).await?)?,
        Action::Availability {
            availability,
            generation,
            reason,
        } => json_value(
            &client
                .set_node_availability_with_operation_id(
                    id.as_deref().expect("write id"),
                    availability,
                    generation,
                    reason,
                )
                .await?,
        )?,
        Action::Profile {
            profile,
            generation,
            reason,
        } => json_value(
            &client
                .set_node_profile_with_operation_id(
                    id.as_deref().expect("write id"),
                    profile,
                    generation,
                    reason,
                )
                .await?,
        )?,
        Action::Join(join) => {
            let mut node = node_client(&join, &profile, token).await?;
            let result = if let Some(signer) = signer.as_mut() {
                signer.admit(&mut client, &mut node, &join).await
            } else {
                ClusterClient::admit_node_with_operation_ids(
                &mut client,
                &mut node,
                &join.node,
                join.generation,
                &join.reason,
                join.ids,
            )
                .await
            };
            let closed = node.close().await;
            let member = result?;
            closed?;
            json!({"member": member, "challenge_operation_id": join.ids.challenge})
        }
        Action::CertificatePrepare {
            join,
            fingerprint,
            ttl,
            overlap,
        } => {
            let mut node = node_client(&join, &profile, token).await?;
            let result = if let Some(signer) = signer.as_mut() {
                signer.prepare(&mut client, &mut node, &join, fingerprint, (ttl, overlap)).await
            } else {
                ClusterClient::prepare_node_certificate_rollout_with_operation_ids(
                &mut client,
                &mut node,
                &join.node,
                fingerprint,
                join.generation.expect("certificate generation"),
                ttl,
                overlap,
                &join.reason,
                join.ids,
            )
                .await
            };
            let closed = node.close().await;
            let (member, rollout) = result?;
            closed?;
            json!({"member": member, "rollout": rollout, "challenge_operation_id": join.ids.challenge})
        }
        Action::MemberState {
            node_id,
            state,
            generation,
            reason,
        } => {
            let member = if let Some(signer) = signer.as_mut() {
                let actor = signer.actor(&mut client).await?;
                signer.member(&mut client, AuthorityCommand::SetMemberState {
                    operation_id: id.clone().expect("write id"), node_id, state,
                    expected_generation: generation, actor, reason, proposed_at: chrono::Utc::now(),
                }).await?
            } else {
                client
                .set_cluster_member_state_with_operation_id(
                    id.as_deref().expect("write id"),
                    node_id,
                    state,
                    generation,
                    reason,
                )
                .await?
            };
            json_value(&member)?
        },
        Action::CertificateFinish {
            node_id,
            abort,
            generation,
            reason,
        } => {
            let member = if let Some(signer) = signer.as_mut() {
                let actor = signer.actor(&mut client).await?;
                let operation_id = id.clone().expect("write id");
                let command = if abort {
                    AuthorityCommand::AbortMemberCertificateRollout {operation_id, node_id, expected_generation: generation, actor, reason, proposed_at: chrono::Utc::now()}
                } else {
                    AuthorityCommand::FinalizeMemberCertificateRollout {operation_id, node_id, expected_generation: generation, actor, reason, proposed_at: chrono::Utc::now()}
                };
                match signer.submit(&mut client, command).await? {
                    AuthorityResponse::CertificateRolloutUpdated {member, ..} => member,
                    _ => return Err(SdkError::Kernel("unexpected signed certificate response".into())),
                }
            } else if abort {
                client
                    .abort_cluster_member_certificate_rollout_with_operation_id(
                        id.as_deref().expect("write id"),
                        node_id,
                        generation,
                        reason,
                    )
                    .await?
            } else {
                client
                    .finalize_cluster_member_certificate_rollout_with_operation_id(
                        id.as_deref().expect("write id"),
                        node_id,
                        generation,
                        reason,
                    )
                    .await?
            };
            json!({"member": member})
        }
        Action::Fence {
            agent_id,
            proof,
            retire,
            reason,
        } => {
            let fence = if retire {
                client
                    .retire_agent_mutation_fence_with_operation_id(
                        id.as_deref().expect("write id"),
                        agent_id,
                        proof,
                        reason,
                    )
                    .await?
            } else {
                client
                    .install_agent_mutation_fence_with_operation_id(
                        id.as_deref().expect("write id"),
                        agent_id,
                        proof,
                        reason,
                    )
                    .await?
            };
            json_value(&fence)?
        }
        Action::Unavailable(_) => unreachable!(),
    };
    client.close().await?;
    Ok(match id {
        Some(id) => json!({"operation_id": id, "record": record}),
        None => record,
    })
}
