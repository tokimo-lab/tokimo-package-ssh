use serde::Serialize;
use ts_rs::TS;

use crate::client::{self, SshCredentials, shell_escape};
use crate::error::SshError;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshFileEntry {
    pub name: String,
    pub is_dir: bool,
    #[ts(type = "number")]
    pub size: u64,
    /// Octal permission string, e.g. "0755"
    pub mode: Option<String>,
    /// Owner user name
    pub owner: Option<String>,
    /// Owner group name
    pub group: Option<String>,
    /// ISO 8601 modified time
    pub modified_at: Option<String>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshLsResponse {
    pub path: String,
    pub entries: Vec<SshFileEntry>,
}

#[derive(Debug, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SshFileContentResponse {
    pub path: String,
    pub content: String,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// List remote directory entries.
pub async fn list_dir(creds: &SshCredentials, path: &str) -> Result<SshLsResponse, SshError> {
    let safe_path = shell_escape(path);
    let cmd = format!(
        "if [ -d '{safe_path}' ]; then find '{safe_path}' -maxdepth 1 -mindepth 1 -printf '%y\\t%s\\t%m\\t%u\\t%g\\t%T@\\t%f\\n' 2>/dev/null; echo '---END---'; else echo '---NOTFOUND---'; fi"
    );
    let output = client::exec(creds, &cmd).await?;
    if output.trim().starts_with("---NOTFOUND---") {
        return Err(SshError::NotFound(format!("Path does not exist: {path}")));
    }
    Ok(SshLsResponse {
        path: path.to_string(),
        entries: parse_ls_output(&output),
    })
}

/// Entry from recursive directory listing.
#[derive(Debug)]
pub struct SshRecursiveEntry {
    /// Path relative to the root directory.
    pub rel_path: String,
    pub is_dir: bool,
    pub size: u64,
}

/// Recursively list all entries under a directory.
/// Returns entries with paths relative to the given root directory.
/// Directories are listed before their children (depth-first order).
pub async fn list_dir_recursive(creds: &SshCredentials, path: &str) -> Result<Vec<SshRecursiveEntry>, SshError> {
    let safe_path = shell_escape(path);
    // %y = type (d/f), %s = size, %P = path relative to starting point
    let cmd = format!(
        "if [ -d '{safe_path}' ]; then find '{safe_path}' -mindepth 1 -printf '%y\\t%s\\t%P\\n' 2>/dev/null; echo '---END---'; else echo '---NOTFOUND---'; fi"
    );
    let output = client::exec(creds, &cmd).await?;
    if output.trim().starts_with("---NOTFOUND---") {
        return Err(SshError::NotFound(format!("Path does not exist: {path}")));
    }
    Ok(parse_recursive_output(&output))
}

/// Create a directory on the remote host.
pub async fn mkdir(creds: &SshCredentials, path: &str) -> Result<(), SshError> {
    let safe = shell_escape(path);
    client::exec(creds, &format!("mkdir -p '{safe}'")).await?;
    Ok(())
}

/// Delete a file or directory on the remote host.
pub async fn rm(creds: &SshCredentials, path: &str) -> Result<(), SshError> {
    let safe = shell_escape(path);
    client::exec(creds, &format!("rm -rf '{safe}'")).await?;
    Ok(())
}

/// Rename/move a file on the remote host.
pub async fn rename(creds: &SshCredentials, from: &str, to: &str) -> Result<(), SshError> {
    let from_safe = shell_escape(from);
    let to_safe = shell_escape(to);
    client::exec(creds, &format!("mv '{from_safe}' '{to_safe}'")).await?;
    Ok(())
}

/// Move a file/directory into a target directory on the remote host.
pub async fn mv_to_dir(creds: &SshCredentials, from: &str, to_dir: &str) -> Result<(), SshError> {
    let from_safe = shell_escape(from);
    let to_dir_safe = shell_escape(to_dir);
    // `mv` into a directory preserves the basename automatically
    client::exec(creds, &format!("mv '{from_safe}' '{to_dir_safe}/'")).await?;
    Ok(())
}

/// Read a text file from the remote host.
pub async fn read_file(creds: &SshCredentials, path: &str) -> Result<SshFileContentResponse, SshError> {
    let safe = shell_escape(path);
    let content = client::exec(creds, &format!("cat '{safe}'")).await?;
    Ok(SshFileContentResponse {
        path: path.to_string(),
        content,
    })
}

/// Write text content to a file on the remote host.
pub async fn write_file(creds: &SshCredentials, path: &str, content: &str) -> Result<(), SshError> {
    let safe = shell_escape(path);
    let cmd = format!("cat > '{safe}'");
    client::exec_with_stdin(creds, &cmd, content.as_bytes()).await?;
    Ok(())
}

/// Download a file as raw bytes from the remote host.
pub async fn download_file(creds: &SshCredentials, path: &str) -> Result<Vec<u8>, SshError> {
    let safe = shell_escape(path);
    client::exec_bytes(creds, &format!("cat '{safe}'")).await
}

/// Stream a file from the remote host without buffering the full content.
///
/// Returns a channel receiver that yields chunks as they arrive from SSH.
/// The HTTP handler can pipe this directly to the response body for instant
/// browser download prompts on large files.
pub async fn download_stream(
    creds: &SshCredentials,
    path: &str,
) -> Result<tokio::sync::mpsc::Receiver<Result<bytes::Bytes, SshError>>, SshError> {
    let safe = shell_escape(path);
    client::exec_stream(creds, &format!("cat '{safe}'")).await
}

/// Upload raw bytes to a file on the remote host.
/// Uses `dd` with input piped via stdin and `bs=65536` for reasonable performance.
pub async fn upload_file(creds: &SshCredentials, path: &str, data: &[u8]) -> Result<(), SshError> {
    let safe = shell_escape(path);
    let cmd = format!("dd of='{safe}' bs=65536 2>/dev/null");
    client::exec_with_stdin(creds, &cmd, data).await?;
    Ok(())
}

/// Stream-upload a file to the remote host.
///
/// Chunks received from `rx` are piped directly to the remote `dd` command
/// via SSH stdin — no full buffering on the server side.
pub async fn upload_stream(
    creds: &SshCredentials,
    path: &str,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<(), SshError> {
    let safe = shell_escape(path);
    let cmd = format!("dd of='{safe}' bs=65536 2>/dev/null");
    client::exec_with_stdin_stream(creds, &cmd, rx).await
}

// ── Parsers ──────────────────────────────────────────────────────────────────

fn parse_ls_output(output: &str) -> Vec<SshFileEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        if line == "---END---" || line.is_empty() {
            continue;
        }
        // Format: type \t size \t mode \t user \t group \t epoch \t name
        let parts: Vec<&str> = line.splitn(7, '\t').collect();
        if parts.len() < 7 {
            // Fallback: old 3-field format (type \t size \t name)
            let old_parts: Vec<&str> = line.splitn(3, '\t').collect();
            if old_parts.len() < 3 {
                continue;
            }
            let file_type = old_parts[0];
            let size: u64 = old_parts[1].parse().unwrap_or(0);
            let name = old_parts[2].to_string();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let is_dir = file_type == "d";
            entries.push(SshFileEntry {
                name,
                is_dir,
                size: if is_dir { 0 } else { size },
                mode: None,
                owner: None,
                group: None,
                modified_at: None,
            });
            continue;
        }
        let file_type = parts[0];
        let size: u64 = parts[1].parse().unwrap_or(0);
        let mode_raw = parts[2];
        let owner = parts[3].to_string();
        let group = parts[4].to_string();
        let epoch_str = parts[5];
        let name = parts[6].to_string();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        let is_dir = file_type == "d";
        let mode = format!("{mode_raw:0>4}");
        // Convert epoch seconds to ISO 8601
        let modified_at = epoch_str
            .split('.')
            .next()
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339()));
        entries.push(SshFileEntry {
            name,
            is_dir,
            size: if is_dir { 0 } else { size },
            mode: Some(mode),
            owner: Some(owner),
            group: Some(group),
            modified_at,
        });
    }
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    entries
}

fn parse_recursive_output(output: &str) -> Vec<SshRecursiveEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        if line == "---END---" || line.is_empty() {
            continue;
        }
        // Format: type \t size \t relative_path
        let parts: Vec<&str> = line.splitn(3, '\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let is_dir = parts[0] == "d";
        let size: u64 = if is_dir { 0 } else { parts[1].parse().unwrap_or(0) };
        let rel_path = parts[2].to_string();
        if rel_path.is_empty() {
            continue;
        }
        entries.push(SshRecursiveEntry { rel_path, is_dir, size });
    }
    entries
}
