use serde::Serialize;
use ts_rs::TS;

use crate::client::{self, SshCredentials};
use crate::error::SshError;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshHostStats {
    pub cpu_usage_percent: f64,
    #[ts(type = "number")]
    pub mem_total_bytes: u64,
    #[ts(type = "number")]
    pub mem_used_bytes: u64,
    #[ts(type = "number")]
    pub mem_available_bytes: u64,
    pub mem_usage_percent: f64,
    #[ts(type = "number")]
    pub swap_total_bytes: u64,
    #[ts(type = "number")]
    pub swap_used_bytes: u64,
    #[ts(type = "number")]
    pub mem_buffers_bytes: u64,
    #[ts(type = "number")]
    pub mem_cached_bytes: u64,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshProcessEntry {
    pub pid: u32,
    pub user: String,
    pub cpu: f64,
    pub mem: f64,
    #[ts(type = "number")]
    pub vsz_kb: u64,
    #[ts(type = "number")]
    pub rss_kb: u64,
    pub stat: String,
    pub command: String,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshPsResponse {
    pub processes: Vec<SshProcessEntry>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDiskEntry {
    pub filesystem: String,
    pub mount_point: String,
    #[ts(type = "number")]
    pub total_bytes: u64,
    #[ts(type = "number")]
    pub used_bytes: u64,
    #[ts(type = "number")]
    pub available_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshDfResponse {
    pub disks: Vec<SshDiskEntry>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Fetch remote host CPU + memory usage.
pub async fn get_stats(creds: &SshCredentials) -> Result<SshHostStats, SshError> {
    // htop-compatible CPU calculation (see htop LinuxMachine.c):
    //   guest is already in user, guestnice in nice → subtract them
    //   idle_all = idle + iowait
    //   sys_all  = system + irq + softirq
    //   virt_all = guest + guestnice
    //   total    = (user-guest) + (nice-guestnice) + sys_all + idle_all + steal + virt_all
    // We output: total idle_all (as integers via printf to avoid awk float truncation)
    let script = r#"
read_cpu() { awk '/^cpu / {u=$2; n=$3; s=$4; id=$5; io=$6; ir=$7; si=$8; st=$9; g=$10; gn=$11; ua=u-g; na=n-gn; ia=id+io; sa=s+ir+si; va=g+gn; t=ua+na+sa+ia+st+va; printf "%.0f %.0f\n",t,ia}' /proc/stat; }
cpu1=$(read_cpu);
sleep 0.2;
cpu2=$(read_cpu);
echo "CPU $cpu1 $cpu2";
awk '/MemTotal:|MemAvailable:|Buffers:|^Cached:|SwapTotal:|SwapFree:/ {print $1, $2}' /proc/meminfo
"#;
    let output = client::exec(creds, script).await?;
    Ok(parse_host_stats(&output))
}

/// List remote processes (sorted by CPU desc).
pub async fn list_processes(creds: &SshCredentials) -> Result<SshPsResponse, SshError> {
    let cmd = "ps aux --sort=-%cpu 2>/dev/null || ps aux 2>/dev/null; echo '---PS_END---'";
    let output = client::exec(creds, cmd).await?;
    Ok(SshPsResponse {
        processes: parse_ps_output(&output),
    })
}

/// Kill a process on the remote host.
pub async fn kill_process(creds: &SshCredentials, pid: u32, signal: &str) -> Result<(), SshError> {
    if !signal.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SshError::BadInput("invalid signal".into()));
    }
    let cmd = format!("kill -{signal} {pid} 2>&1");
    let output = client::exec(creds, &cmd).await?;
    if output.contains("No such process") {
        return Err(SshError::NotFound("process not found".into()));
    }
    Ok(())
}

/// Fetch remote host disk usage.
pub async fn get_disk_usage(creds: &SshCredentials) -> Result<SshDfResponse, SshError> {
    let script = "df -B1 --output=source,target,size,used,avail 2>/dev/null | tail -n +2";
    let output = client::exec(creds, script).await?;
    Ok(SshDfResponse {
        disks: parse_df_output(&output),
    })
}

// ── Parsers ──────────────────────────────────────────────────────────────────

fn parse_host_stats(output: &str) -> SshHostStats {
    let mut cpu_usage = 0.0;
    let mut mem_total_kb: u64 = 0;
    let mut mem_available_kb: u64 = 0;
    let mut mem_buffers_kb: u64 = 0;
    let mut mem_cached_kb: u64 = 0;
    let mut swap_total_kb: u64 = 0;
    let mut swap_free_kb: u64 = 0;

    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("CPU ") {
            let parts: Vec<f64> = rest.split_whitespace().filter_map(|s| s.parse().ok()).collect();
            if parts.len() >= 4 {
                let total_delta = parts[2] - parts[0];
                let idle_delta = parts[3] - parts[1];
                if total_delta > 0.0 {
                    cpu_usage = ((total_delta - idle_delta) / total_delta * 100.0).clamp(0.0, 100.0);
                }
            }
        } else if let Some(rest) = line.strip_prefix("MemTotal:") {
            mem_total_kb = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            mem_available_kb = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Buffers:") {
            mem_buffers_kb = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Cached:") {
            mem_cached_kb = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("SwapTotal:") {
            swap_total_kb = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("SwapFree:") {
            swap_free_kb = rest.trim().parse().unwrap_or(0);
        }
    }

    let mem_total_bytes = mem_total_kb * 1024;
    let mem_available_bytes = mem_available_kb * 1024;
    let mem_used_bytes = mem_total_bytes.saturating_sub(mem_available_bytes);
    let mem_usage_percent = if mem_total_bytes > 0 {
        (mem_used_bytes as f64 / mem_total_bytes as f64 * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };
    let swap_total_bytes = swap_total_kb * 1024;
    let swap_used_bytes = swap_total_bytes.saturating_sub(swap_free_kb * 1024);

    SshHostStats {
        cpu_usage_percent: (cpu_usage * 10.0).round() / 10.0,
        mem_total_bytes,
        mem_used_bytes,
        mem_available_bytes,
        mem_usage_percent: (mem_usage_percent * 10.0).round() / 10.0,
        swap_total_bytes,
        swap_used_bytes,
        mem_buffers_bytes: mem_buffers_kb * 1024,
        mem_cached_bytes: mem_cached_kb * 1024,
    }
}

fn parse_ps_output(output: &str) -> Vec<SshProcessEntry> {
    let mut entries = Vec::new();
    let mut header_seen = false;
    for line in output.lines() {
        if line == "---PS_END---" || line.is_empty() {
            continue;
        }
        if !header_seen {
            if line.starts_with("USER") || line.starts_with("user") {
                header_seen = true;
            }
            continue;
        }
        // ps aux columns: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
        let mut parts = line.split_whitespace();
        let user = match parts.next() {
            Some(u) => u.to_string(),
            None => continue,
        };
        let pid: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let cpu: f64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let mem: f64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let vsz_kb: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let rss_kb: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let _tty = parts.next();
        let stat = parts.next().unwrap_or("").to_string();
        let _start = parts.next();
        let _time = parts.next();
        let command: String = parts.collect::<Vec<_>>().join(" ");
        if pid == 0 && command.is_empty() {
            continue;
        }
        entries.push(SshProcessEntry {
            pid,
            user,
            cpu,
            mem,
            vsz_kb,
            rss_kb,
            stat,
            command,
        });
    }
    entries
}

fn parse_df_output(output: &str) -> Vec<SshDiskEntry> {
    let mut disks = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let filesystem = parts[0].to_string();
        if filesystem.starts_with("tmpfs")
            || filesystem.starts_with("devtmpfs")
            || filesystem == "none"
            || filesystem == "udev"
            || filesystem == "overlay"
        {
            continue;
        }
        let mount_point = parts[1].to_string();
        let total_bytes: u64 = parts[2].parse().unwrap_or(0);
        let used_bytes: u64 = parts[3].parse().unwrap_or(0);
        let available_bytes: u64 = parts[4].parse().unwrap_or(0);
        if total_bytes == 0 {
            continue;
        }
        let usage_percent = ((used_bytes as f64 / total_bytes as f64) * 100.0 * 10.0).round() / 10.0;
        disks.push(SshDiskEntry {
            filesystem,
            mount_point,
            total_bytes,
            used_bytes,
            available_bytes,
            usage_percent,
        });
    }
    disks
}
