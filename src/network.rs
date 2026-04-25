use std::collections::{HashMap, HashSet};

use serde::Serialize;
use ts_rs::TS;

use crate::client::{self, SshCredentials};
use crate::error::SshError;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshNetworkInterfaceEntry {
    pub name: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: String,
    pub is_up: bool,
    #[ts(type = "number | null")]
    pub mtu: Option<u64>,
    #[ts(type = "number")]
    pub rx_bytes: u64,
    #[ts(type = "number")]
    pub tx_bytes: u64,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshListeningSocketEntry {
    pub protocol: String,
    pub local_address: String,
    pub peer_address: String,
    pub state: String,
    pub process: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshConnectionEntry {
    pub protocol: String,
    pub local_address: String,
    pub peer_address: String,
    pub state: String,
    pub process: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshRouteEntry {
    pub destination: String,
    pub gateway: String,
    pub iface: String,
    pub protocol: String,
    pub scope: String,
    pub metric: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshNetworkResponse {
    pub interfaces: Vec<SshNetworkInterfaceEntry>,
    pub listening: Vec<SshListeningSocketEntry>,
    pub connections: Vec<SshConnectionEntry>,
    pub routes: Vec<SshRouteEntry>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Fetch remote host network info (interfaces, sockets, connections, routes).
pub async fn get_network_info(creds: &SshCredentials) -> Result<SshNetworkResponse, SshError> {
    let script = r"echo '===INTERFACES===';
ip -o addr show 2>/dev/null || ifconfig 2>/dev/null;
echo '===LINKS===';
ip -o link show 2>/dev/null;
echo '===LISTENING===';
ss -tunlp 2>/dev/null | tail -n +2;
echo '===CONNECTIONS===';
ss -tunp state established 2>/dev/null | tail -n +2;
echo '===RX_TX===';
cat /proc/net/dev 2>/dev/null | tail -n +3;
echo '===ROUTES===';
ip route show 2>/dev/null";

    let output = client::exec(creds, script).await?;
    Ok(parse_network_output(&output))
}

// ── Parsers ──────────────────────────────────────────────────────────────────

fn find_section(sections: &[&str], name: &str) -> String {
    for i in 0..sections.len() {
        if sections[i].trim() == name && i + 1 < sections.len() {
            return sections[i + 1].to_string();
        }
    }
    String::new()
}

fn extract_process_name(raw: &str) -> String {
    if let Some(start) = raw.find("((\"")
        && let Some(end) = raw[start + 3..].find('"')
    {
        return raw[start + 3..start + 3 + end].to_string();
    }
    raw.to_string()
}

#[allow(clippy::too_many_lines)]
fn parse_network_output(output: &str) -> SshNetworkResponse {
    let sections: Vec<&str> = output.split("===").collect();

    let iface_section = find_section(&sections, "INTERFACES");
    let links_section = find_section(&sections, "LINKS");
    let listening_section = find_section(&sections, "LISTENING");
    let connections_section = find_section(&sections, "CONNECTIONS");
    let rxtx_section = find_section(&sections, "RX_TX");
    let routes_section = find_section(&sections, "ROUTES");

    // Parse ip -o addr: "2: eth0    inet 172.17.0.2/16 ..."
    let mut iface_map: HashMap<String, Vec<String>> = HashMap::new();
    for line in iface_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let name = parts[1].trim_end_matches(':').to_string();
            let addr = parts[3].to_string();
            iface_map.entry(name).or_default().push(addr);
        }
    }

    // Parse ip -o link: "2: eth0: <...UP...> ... link/ether aa:bb:cc ..."
    let mut link_info: HashMap<String, (String, bool, Option<u64>)> = HashMap::new();
    for line in links_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            // Strip @ifN suffix (e.g. "veth2212927@if2" → "veth2212927")
            let raw_name = parts[1].trim_end_matches(':');
            let name = raw_name.find('@').map_or(raw_name, |i| &raw_name[..i]).to_string();
            let is_up = line.contains("UP");
            let mut mac = String::new();
            let mut mtu: Option<u64> = None;
            for (i, p) in parts.iter().enumerate() {
                if *p == "link/ether" && i + 1 < parts.len() {
                    mac = parts[i + 1].to_string();
                }
                if *p == "mtu" && i + 1 < parts.len() {
                    mtu = parts[i + 1].parse().ok();
                }
            }
            link_info.insert(name, (mac, is_up, mtu));
        }
    }

    // Parse /proc/net/dev for RX/TX bytes
    let mut rxtx_map: HashMap<String, (u64, u64)> = HashMap::new();
    for line in rxtx_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, rest)) = line.split_once(':') {
            let name = name.trim().to_string();
            let nums: Vec<u64> = rest.split_whitespace().filter_map(|s| s.parse().ok()).collect();
            if nums.len() >= 9 {
                rxtx_map.insert(name, (nums[0], nums[8]));
            }
        }
    }

    // Merge interfaces
    let mut all_names: HashSet<String> = HashSet::new();
    for name in iface_map.keys() {
        all_names.insert(name.clone());
    }
    for name in link_info.keys() {
        all_names.insert(name.clone());
    }
    let mut interfaces: Vec<SshNetworkInterfaceEntry> = all_names
        .iter()
        .map(|name| {
            let ip_addresses = iface_map.get(name).cloned().unwrap_or_default();
            let (mac_address, is_up, mtu) = link_info.get(name).cloned().unwrap_or_default();
            let (rx_bytes, tx_bytes) = rxtx_map.get(name).copied().unwrap_or((0, 0));
            SshNetworkInterfaceEntry {
                name: name.clone(),
                ip_addresses,
                mac_address,
                is_up,
                mtu,
                rx_bytes,
                tx_bytes,
            }
        })
        .collect();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));

    // Parse listening sockets
    let mut listening = Vec::new();
    for line in listening_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let protocol = parts[0].to_string();
            let state = parts[1].to_string();
            let local_address = parts[4].to_string();
            let peer_address = if parts.len() > 5 {
                parts[5].to_string()
            } else {
                String::new()
            };
            let process = if parts.len() > 6 {
                let raw = parts[6..].join(" ");
                extract_process_name(&raw)
            } else {
                String::new()
            };
            listening.push(SshListeningSocketEntry {
                protocol,
                local_address,
                peer_address,
                state,
                process,
            });
        }
    }

    // Parse established connections
    let mut connections = Vec::new();
    for line in connections_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let protocol = parts[0].to_string();
            let local_address = parts[3].to_string();
            let peer_address = parts[4].to_string();
            let process = if parts.len() > 5 {
                let raw = parts[5..].join(" ");
                extract_process_name(&raw)
            } else {
                String::new()
            };
            connections.push(SshConnectionEntry {
                protocol,
                local_address,
                peer_address,
                state: "ESTAB".to_string(),
                process,
            });
        }
    }

    // Parse routes
    let mut routes = Vec::new();
    for line in routes_section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let destination = parts[0].to_string();
        let mut gateway = String::new();
        let mut iface = String::new();
        let mut protocol = String::new();
        let mut scope = String::new();
        let mut metric = String::new();
        let mut i = 1;
        while i < parts.len() {
            match parts[i] {
                "via" if i + 1 < parts.len() => {
                    gateway = parts[i + 1].to_string();
                    i += 2;
                }
                "dev" if i + 1 < parts.len() => {
                    iface = parts[i + 1].to_string();
                    i += 2;
                }
                "proto" if i + 1 < parts.len() => {
                    protocol = parts[i + 1].to_string();
                    i += 2;
                }
                "scope" if i + 1 < parts.len() => {
                    scope = parts[i + 1].to_string();
                    i += 2;
                }
                "metric" if i + 1 < parts.len() => {
                    metric = parts[i + 1].to_string();
                    i += 2;
                }
                _ => i += 1,
            }
        }
        routes.push(SshRouteEntry {
            destination,
            gateway,
            iface,
            protocol,
            scope,
            metric,
        });
    }

    SshNetworkResponse {
        interfaces,
        listening,
        connections,
        routes,
    }
}
