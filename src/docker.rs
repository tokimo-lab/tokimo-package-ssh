use std::collections::HashMap;

use serde::Serialize;
use ts_rs::TS;

use crate::client::{self, SshCredentials};
use crate::error::SshError;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerContainerEntry {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    #[ts(type = "number")]
    pub created_ts: i64,
    pub ports: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerPsResponse {
    pub available: bool,
    pub containers: Vec<DockerContainerEntry>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerImageEntry {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
    pub created: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerImagesResponse {
    pub images: Vec<DockerImageEntry>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerNetworkEntry {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
    pub ipam_subnet: String,
    pub ipam_gateway: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerNetworksResponse {
    pub networks: Vec<DockerNetworkEntry>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerVolumeEntry {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub scope: String,
    pub created: String,
    pub size: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerVolumesResponse {
    pub volumes: Vec<DockerVolumeEntry>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerContainerInspect {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub pid: i64,
    pub started_at: String,
    pub finished_at: String,
    pub restart_count: i64,
    pub platform: String,
    pub env: Vec<String>,
    pub cmd: String,
    pub entrypoint: String,
    pub working_dir: String,
    pub hostname: String,
    pub network_mode: String,
    pub port_bindings: String,
    pub mounts: Vec<DockerMountEntry>,
    pub networks: Vec<DockerContainerNetwork>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerMountEntry {
    pub source: String,
    pub destination: String,
    pub mode: String,
    pub rw: bool,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerContainerNetwork {
    pub name: String,
    pub ip_address: String,
    pub gateway: String,
    pub mac_address: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerInspectResponse {
    pub container: DockerContainerInspect,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct DockerStatsEntry {
    pub container_id: String,
    pub name: String,
    pub cpu_percent: String,
    pub mem_usage: String,
    pub mem_limit: String,
    pub mem_percent: String,
    pub net_io: String,
    pub block_io: String,
    pub pids: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerStatsResponse {
    pub stats: Vec<DockerStatsEntry>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerLogsResponse {
    pub logs: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDockerPruneResponse {
    pub output: String,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Validate a Docker resource ID (container, image, network, volume).
fn validate_id(id: &str) -> Result<&str, SshError> {
    if id.is_empty() || id.len() > 128 {
        return Err(SshError::BadInput("invalid docker resource id".into()));
    }
    if id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':' || c == '/')
    {
        Ok(id)
    } else {
        Err(SshError::BadInput("invalid docker resource id".into()))
    }
}

fn parse_docker_time(s: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(s.get(..19).unwrap_or(""), "%Y-%m-%d %H:%M:%S")
        .map_or(0, |dt| dt.and_utc().timestamp())
}

async fn docker_action(creds: &SshCredentials, action: &str, resource_id: &str) -> Result<(), SshError> {
    let id = validate_id(resource_id)?;
    client::exec(creds, &format!("docker {action} {id}")).await?;
    Ok(())
}

// ── Container operations ─────────────────────────────────────────────────────

/// List Docker containers on the remote host.
pub async fn ps(creds: &SshCredentials) -> Result<SshDockerPsResponse, SshError> {
    let script = r"command -v docker >/dev/null 2>&1 && echo '__DOCKER_OK__' && docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.CreatedAt}}\t{{.Ports}}' 2>/dev/null || echo '__NO_DOCKER__'";
    let output = client::exec(creds, script).await?;

    if output.contains("__NO_DOCKER__") {
        return Ok(SshDockerPsResponse {
            available: false,
            containers: Vec::new(),
        });
    }

    let mut containers = Vec::new();
    for line in output.lines() {
        if line.starts_with("__DOCKER_OK__") || line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(7, '\t').collect();
        if parts.len() < 5 {
            continue;
        }
        containers.push(DockerContainerEntry {
            id: parts[0].to_string(),
            name: parts[1].to_string(),
            image: parts[2].to_string(),
            state: parts[3].to_string(),
            status: parts.get(4).unwrap_or(&"").to_string(),
            created_ts: parse_docker_time(parts.get(5).unwrap_or(&"")),
            ports: parts.get(6).unwrap_or(&"").to_string(),
        });
    }

    Ok(SshDockerPsResponse {
        available: true,
        containers,
    })
}

pub async fn start(creds: &SshCredentials, container_id: &str) -> Result<(), SshError> {
    docker_action(creds, "start", container_id).await
}

pub async fn stop(creds: &SshCredentials, container_id: &str) -> Result<(), SshError> {
    docker_action(creds, "stop", container_id).await
}

pub async fn restart(creds: &SshCredentials, container_id: &str) -> Result<(), SshError> {
    docker_action(creds, "restart", container_id).await
}

pub async fn rm(creds: &SshCredentials, container_id: &str) -> Result<(), SshError> {
    docker_action(creds, "rm", container_id).await
}

pub async fn pause(creds: &SshCredentials, container_id: &str) -> Result<(), SshError> {
    docker_action(creds, "pause", container_id).await
}

pub async fn unpause(creds: &SshCredentials, container_id: &str) -> Result<(), SshError> {
    docker_action(creds, "unpause", container_id).await
}

/// Get recent container logs.
pub async fn logs(creds: &SshCredentials, container_id: &str, tail: u32) -> Result<SshDockerLogsResponse, SshError> {
    let cid = validate_id(container_id)?;
    let tail = tail.min(2000);
    let output = client::exec(creds, &format!("docker logs --tail {tail} {cid} 2>&1")).await?;
    Ok(SshDockerLogsResponse { logs: output })
}

/// Get resource usage of all running containers.
pub async fn stats(creds: &SshCredentials) -> Result<SshDockerStatsResponse, SshError> {
    let script = r"docker stats --no-stream --format '{{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}' 2>/dev/null";
    let output = client::exec(creds, script).await?;

    let mut entries = Vec::new();
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(8, '\t').collect();
        if parts.len() < 5 {
            continue;
        }
        let mem_parts: Vec<&str> = parts.get(3).unwrap_or(&"").split(" / ").collect();
        entries.push(DockerStatsEntry {
            container_id: parts[0].to_string(),
            name: parts[1].to_string(),
            cpu_percent: parts[2].to_string(),
            mem_usage: mem_parts.first().unwrap_or(&"").to_string(),
            mem_limit: mem_parts.get(1).unwrap_or(&"").to_string(),
            mem_percent: parts.get(4).unwrap_or(&"").to_string(),
            net_io: parts.get(5).unwrap_or(&"").to_string(),
            block_io: parts.get(6).unwrap_or(&"").to_string(),
            pids: parts.get(7).unwrap_or(&"").to_string(),
        });
    }

    Ok(SshDockerStatsResponse { stats: entries })
}

/// Inspect a container (detailed JSON info).
pub async fn inspect(creds: &SshCredentials, container_id: &str) -> Result<SshDockerInspectResponse, SshError> {
    let cid = validate_id(container_id)?;
    let output = client::exec(creds, &format!("docker inspect {cid} 2>/dev/null")).await?;

    let parsed: serde_json::Value = serde_json::from_str(&output).map_err(|e| SshError::Parse(format!("json: {e}")))?;

    let c = parsed
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| SshError::Parse("empty inspect".into()))?;

    let mounts = c["Mounts"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|m| DockerMountEntry {
                    source: m["Source"].as_str().unwrap_or("").to_string(),
                    destination: m["Destination"].as_str().unwrap_or("").to_string(),
                    mode: m["Mode"].as_str().unwrap_or("").to_string(),
                    rw: m["RW"].as_bool().unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();

    let networks = c["NetworkSettings"]["Networks"]
        .as_object()
        .map(|obj| {
            obj.iter()
                .map(|(name, v)| DockerContainerNetwork {
                    name: name.clone(),
                    ip_address: v["IPAddress"].as_str().unwrap_or("").to_string(),
                    gateway: v["Gateway"].as_str().unwrap_or("").to_string(),
                    mac_address: v["MacAddress"].as_str().unwrap_or("").to_string(),
                })
                .collect()
        })
        .unwrap_or_default();

    let env = c["Config"]["Env"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let port_bindings_val = &c["HostConfig"]["PortBindings"];
    let port_bindings = if port_bindings_val.is_object() {
        serde_json::to_string(port_bindings_val).unwrap_or_default()
    } else {
        String::new()
    };

    let container = DockerContainerInspect {
        id: c["Id"].as_str().unwrap_or("").to_string(),
        name: c["Name"].as_str().unwrap_or("").trim_start_matches('/').to_string(),
        image: c["Config"]["Image"].as_str().unwrap_or("").to_string(),
        state: c["State"]["Status"].as_str().unwrap_or("").to_string(),
        pid: c["State"]["Pid"].as_i64().unwrap_or(0),
        started_at: c["State"]["StartedAt"].as_str().unwrap_or("").to_string(),
        finished_at: c["State"]["FinishedAt"].as_str().unwrap_or("").to_string(),
        restart_count: c["RestartCount"].as_i64().unwrap_or(0),
        platform: c["Platform"].as_str().unwrap_or("").to_string(),
        env,
        cmd: c["Config"]["Cmd"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" "))
            .unwrap_or_default(),
        entrypoint: c["Config"]["Entrypoint"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" "))
            .unwrap_or_default(),
        working_dir: c["Config"]["WorkingDir"].as_str().unwrap_or("").to_string(),
        hostname: c["Config"]["Hostname"].as_str().unwrap_or("").to_string(),
        network_mode: c["HostConfig"]["NetworkMode"].as_str().unwrap_or("").to_string(),
        port_bindings,
        mounts,
        networks,
    };

    Ok(SshDockerInspectResponse { container })
}

// ── Image operations ─────────────────────────────────────────────────────────

/// List Docker images.
pub async fn images(creds: &SshCredentials) -> Result<SshDockerImagesResponse, SshError> {
    let script =
        r"docker images --format '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}' 2>/dev/null";
    let output = client::exec(creds, script).await?;

    let mut entries = Vec::new();
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() < 4 {
            continue;
        }
        entries.push(DockerImageEntry {
            id: parts[0].to_string(),
            repository: parts[1].to_string(),
            tag: parts[2].to_string(),
            size: parts.get(3).unwrap_or(&"").to_string(),
            created: parts.get(4).unwrap_or(&"").to_string(),
        });
    }

    Ok(SshDockerImagesResponse { images: entries })
}

/// Remove a Docker image.
pub async fn rmi(creds: &SshCredentials, image_id: &str) -> Result<(), SshError> {
    docker_action(creds, "rmi", image_id).await
}

// ── Network operations ───────────────────────────────────────────────────────

/// List Docker networks.
pub async fn networks(creds: &SshCredentials) -> Result<SshDockerNetworksResponse, SshError> {
    let script = r"docker network ls --format '{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}' 2>/dev/null";
    let output = client::exec(creds, script).await?;

    let inspect_script = r"docker network inspect --format '{{.ID}}\t{{range .IPAM.Config}}{{.Subnet}}\t{{.Gateway}}{{end}}' $(docker network ls -q) 2>/dev/null";
    let inspect_output = client::exec(creds, inspect_script).await.unwrap_or_default();

    let mut ipam_map = HashMap::new();
    for line in inspect_output.lines() {
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if !parts.is_empty() {
            let nid = parts[0];
            let subnet = parts.get(1).unwrap_or(&"").to_string();
            let gateway = parts.get(2).unwrap_or(&"").to_string();
            ipam_map.insert(nid.to_string(), (subnet, gateway));
        }
    }

    let mut entries = Vec::new();
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let net_id = parts[0].to_string();
        let (subnet, gateway) = ipam_map.get(&net_id).cloned().unwrap_or((String::new(), String::new()));
        entries.push(DockerNetworkEntry {
            id: net_id,
            name: parts[1].to_string(),
            driver: parts[2].to_string(),
            scope: parts.get(3).unwrap_or(&"").to_string(),
            ipam_subnet: subnet,
            ipam_gateway: gateway,
        });
    }

    Ok(SshDockerNetworksResponse { networks: entries })
}

/// Remove a Docker network.
pub async fn network_rm(creds: &SshCredentials, network_id: &str) -> Result<(), SshError> {
    docker_action(creds, "network rm", network_id).await
}

// ── Volume operations ────────────────────────────────────────────────────────

/// List Docker volumes.
pub async fn volumes(creds: &SshCredentials) -> Result<SshDockerVolumesResponse, SshError> {
    let script =
        r"docker volume ls --format '{{.Name}}\t{{.Driver}}\t{{.Mountpoint}}\t{{.Scope}}\t{{.CreatedAt}}' 2>/dev/null";
    let output = client::exec(creds, script).await?;

    let size_script = r"docker system df -v --format '{{.Name}}\t{{.Size}}' 2>/dev/null | grep -v 'VOLUME' || true";
    let size_output = client::exec(creds, size_script).await.unwrap_or_default();

    let mut size_map = HashMap::new();
    for line in size_output.lines() {
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() == 2 {
            size_map.insert(parts[0].to_string(), parts[1].to_string());
        }
    }

    let mut entries = Vec::new();
    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.is_empty() {
            continue;
        }
        let name = parts[0].to_string();
        let size = size_map.get(&name).cloned().unwrap_or_default();
        entries.push(DockerVolumeEntry {
            name,
            driver: parts.get(1).unwrap_or(&"").to_string(),
            mountpoint: parts.get(2).unwrap_or(&"").to_string(),
            scope: parts.get(3).unwrap_or(&"").to_string(),
            created: parts.get(4).unwrap_or(&"").to_string(),
            size,
        });
    }

    Ok(SshDockerVolumesResponse { volumes: entries })
}

/// Remove a Docker volume.
pub async fn volume_rm(creds: &SshCredentials, volume_name: &str) -> Result<(), SshError> {
    docker_action(creds, "volume rm", volume_name).await
}

// ── Prune operations ─────────────────────────────────────────────────────────

pub async fn prune_images(creds: &SshCredentials) -> Result<SshDockerPruneResponse, SshError> {
    let output = client::exec(creds, "docker image prune -f 2>&1").await?;
    Ok(SshDockerPruneResponse { output })
}

pub async fn prune_volumes(creds: &SshCredentials) -> Result<SshDockerPruneResponse, SshError> {
    let output = client::exec(creds, "docker volume prune -f 2>&1").await?;
    Ok(SshDockerPruneResponse { output })
}

pub async fn prune_networks(creds: &SshCredentials) -> Result<SshDockerPruneResponse, SshError> {
    let output = client::exec(creds, "docker network prune -f 2>&1").await?;
    Ok(SshDockerPruneResponse { output })
}

pub async fn prune_system(creds: &SshCredentials) -> Result<SshDockerPruneResponse, SshError> {
    let output = client::exec(creds, "docker system prune -f 2>&1").await?;
    Ok(SshDockerPruneResponse { output })
}
