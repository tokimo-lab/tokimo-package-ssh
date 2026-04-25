use std::sync::Arc;

use russh::client;
use russh::keys::PrivateKeyWithHashAlg;

use crate::error::SshError;

/// SSH connection credentials (framework-agnostic).
#[derive(Debug, Clone)]
pub struct SshCredentials {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
}

// ── Internal SSH client handler ──

pub(crate) struct SshHandler;

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _server_public_key: &russh::keys::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

// ── Authentication ──

pub(crate) async fn authenticate(
    handle: &mut client::Handle<SshHandler>,
    creds: &SshCredentials,
) -> Result<(), SshError> {
    if creds.auth_method.as_str() == "private_key" {
        let key_pem = creds
            .private_key
            .as_deref()
            .ok_or_else(|| SshError::Auth("no private key provided".into()))?;
        let key = russh::keys::decode_secret_key(key_pem, creds.passphrase.as_deref())
            .map_err(|e| SshError::Auth(format!("failed to decode private key: {e}")))?;
        let key_algo = key.algorithm();
        let best_hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
        let result = handle
            .authenticate_publickey(&creds.username, PrivateKeyWithHashAlg::new(Arc::new(key), best_hash))
            .await
            .map_err(|e| SshError::Auth(format!("publickey auth error: {e}")))?;
        if !result.success() {
            return Err(SshError::Auth(format!(
                "server rejected {key_algo} key for user '{}' — \
                 the key may not be in the server's authorized_keys",
                creds.username,
            )));
        }
    } else {
        let pwd = creds.password.as_deref().unwrap_or("");
        let result = handle
            .authenticate_password(&creds.username, pwd)
            .await
            .map_err(|e| SshError::Auth(format!("password auth error: {e}")))?;
        if !result.success() {
            return Err(SshError::Auth(format!(
                "server rejected password for user '{}'",
                creds.username,
            )));
        }
    }
    Ok(())
}

// ── Exec helpers ──

async fn connect_and_auth(creds: &SshCredentials, timeout_secs: u64) -> Result<client::Handle<SshHandler>, SshError> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(timeout_secs)),
        ..Default::default()
    });
    let addr = (creds.host.as_str(), creds.port);
    let mut handle = client::connect(config, addr, SshHandler)
        .await
        .map_err(|e| SshError::Connection(format!("{e}")))?;
    authenticate(&mut handle, creds).await?;
    Ok(handle)
}

async fn open_exec_channel(
    handle: &client::Handle<SshHandler>,
    cmd: &str,
) -> Result<russh::Channel<client::Msg>, SshError> {
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| SshError::Channel(format!("{e}")))?;
    channel
        .exec(true, cmd)
        .await
        .map_err(|e| SshError::Exec(format!("{e}")))?;
    Ok(channel)
}

async fn read_channel_stdout(channel: russh::Channel<client::Msg>) -> Vec<u8> {
    let mut stdout = Vec::new();
    let (mut read_half, _write_half) = channel.split();
    while let Some(msg) = read_half.wait().await {
        match msg {
            russh::ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    stdout
}

/// Run a command via SSH and return stdout as a String.
pub async fn exec(creds: &SshCredentials, cmd: &str) -> Result<String, SshError> {
    let handle = connect_and_auth(creds, 15).await?;
    let channel = open_exec_channel(&handle, cmd).await?;
    let stdout = read_channel_stdout(channel).await;
    String::from_utf8(stdout).map_err(|e| SshError::Exec(format!("utf8: {e}")))
}

/// Run a command and return stdout as raw bytes.
pub async fn exec_bytes(creds: &SshCredentials, cmd: &str) -> Result<Vec<u8>, SshError> {
    let handle = connect_and_auth(creds, 30).await?;
    let channel = open_exec_channel(&handle, cmd).await?;
    Ok(read_channel_stdout(channel).await)
}

/// Run a command and stream stdout chunks through a Tokio mpsc channel.
///
/// Returns the receiver end immediately — the caller does not wait for the
/// full output to arrive.  The spawned task drives the SSH channel and
/// sends `Ok(Vec<u8>)` chunks (or a terminal `Err`) through the channel.
/// Dropping the receiver aborts the stream gracefully.
pub async fn exec_stream(
    creds: &SshCredentials,
    cmd: &str,
) -> Result<tokio::sync::mpsc::Receiver<Result<bytes::Bytes, SshError>>, SshError> {
    let handle = connect_and_auth(creds, 30).await?;
    let channel = open_exec_channel(&handle, cmd).await?;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, SshError>>(32);

    tokio::spawn(async move {
        // Keep the connection handle alive for the lifetime of the stream.
        let _handle = handle;
        let (mut read_half, _write_half) = channel.split();
        while let Some(msg) = read_half.wait().await {
            #[allow(clippy::collapsible_match)]
            match msg {
                russh::ChannelMsg::Data { data } => {
                    if tx.send(Ok(data)).await.is_err() {
                        // Receiver dropped (client disconnected) — stop gracefully.
                        break;
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        // When tx is dropped the stream signals EOF to the caller.
    });

    Ok(rx)
}

/// Run a command, write stdin data into it, return stdout.
pub async fn exec_with_stdin(creds: &SshCredentials, cmd: &str, stdin_data: &[u8]) -> Result<String, SshError> {
    let handle = connect_and_auth(creds, 30).await?;
    let channel = open_exec_channel(&handle, cmd).await?;
    let (mut read_half, write_half) = channel.split();

    write_half
        .data(stdin_data)
        .await
        .map_err(|e| SshError::Exec(format!("write stdin: {e}")))?;
    write_half
        .eof()
        .await
        .map_err(|e| SshError::Exec(format!("eof: {e}")))?;

    let mut stdout = Vec::new();
    while let Some(msg) = read_half.wait().await {
        match msg {
            russh::ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    String::from_utf8(stdout).map_err(|e| SshError::Exec(format!("utf8: {e}")))
}

/// Run a command, stream stdin data from a channel receiver, discard stdout.
///
/// Each chunk received from `rx` is written to the remote command's stdin.
/// When the receiver closes (sender dropped), EOF is sent. Returns once the
/// remote command finishes.
pub async fn exec_with_stdin_stream(
    creds: &SshCredentials,
    cmd: &str,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<(), SshError> {
    let handle = connect_and_auth(creds, 300).await?;
    let channel = open_exec_channel(&handle, cmd).await?;
    let (mut read_half, write_half) = channel.split();

    // Write chunks as they arrive
    while let Some(chunk) = rx.recv().await {
        write_half
            .data(&chunk[..])
            .await
            .map_err(|e| SshError::Exec(format!("write stdin chunk: {e}")))?;
    }

    write_half
        .eof()
        .await
        .map_err(|e| SshError::Exec(format!("eof: {e}")))?;

    // Drain stdout/wait for remote to close
    while let Some(msg) = read_half.wait().await {
        match msg {
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }

    Ok(())
}

/// Escape a path for safe shell usage (single-quote wrapping).
pub fn shell_escape(s: &str) -> String {
    s.replace('\'', "'\\''")
}
