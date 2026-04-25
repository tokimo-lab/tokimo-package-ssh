use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::client::{self, SshCredentials, SshHandler};
use crate::error::SshError;

/// Marker bytes sent once after the SSH shell is fully ready.
/// The WebSocket client should intercept this and NOT display it.
pub const SSH_READY_MARKER: &[u8] = b"\x01SSH_READY\x01";

/// Input message from the client to the SSH shell.
pub enum ShellInput {
    /// Raw terminal data.
    Data(Vec<u8>),
    /// Resize the terminal.
    Resize { cols: u32, rows: u32 },
}

/// Run an interactive SSH shell session.
///
/// Blocks until the session ends. Sends shell output via `output_tx`,
/// receives client input via `input_rx`. Error messages are also sent
/// through `output_tx` (ANSI-formatted) before returning the error.
pub async fn run_interactive_shell(
    creds: &SshCredentials,
    startup_command: Option<&str>,
    output_tx: mpsc::Sender<Bytes>,
    mut input_rx: mpsc::Receiver<ShellInput>,
) -> Result<(), SshError> {
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(std::time::Duration::from_hours(1)),
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        keepalive_max: 3,
        ..Default::default()
    });

    let addr = (creds.host.as_str(), creds.port);

    // ── Phase 1: TCP + SSH handshake ──
    let _ = output_tx
        .send(Bytes::from(format!(
            "\x1b[90m[ssh] connecting to {}:{} ...\x1b[0m\r\n",
            creds.host, creds.port
        )))
        .await;

    let mut handle = match russh::client::connect(config, addr, SshHandler).await {
        Ok(h) => h,
        Err(e) => {
            let detail = format!(
                "\x1b[31m✗ SSH connection failed\x1b[0m\r\n\
                 \x1b[90m  host:  {}:{}\r\n\
                 \x1b[90m  error: {e}\x1b[0m\r\n\
                 \r\n\
                 \x1b[33mPlease check:\r\n\
                 \x1b[33m  • Is the host reachable from the server?\r\n\
                 \x1b[33m  • Is port {} open?\r\n\
                 \x1b[33m  • Is sshd running on the remote host?\x1b[0m\r\n",
                creds.host, creds.port, creds.port,
            );
            let _ = output_tx.send(Bytes::from(detail)).await;
            return Err(SshError::Connection(format!("{e}")));
        }
    };

    let _ = output_tx
        .send(Bytes::from(format!(
            "\x1b[90m[ssh] connected, authenticating as '{}' ({}) ...\x1b[0m\r\n",
            creds.username, creds.auth_method
        )))
        .await;

    // ── Phase 2: authentication ──
    if let Err(e) = client::authenticate(&mut handle, creds).await {
        let detail = format!(
            "\x1b[31m✗ Authentication failed\x1b[0m\r\n\
             \x1b[90m  host:   {}:{}\r\n\
             \x1b[90m  user:   {}\r\n\
             \x1b[90m  method: {}\r\n\
             \x1b[90m  error:  {e}\x1b[0m\r\n\
             \r\n\
             \x1b[33mNetwork connection succeeded — the problem is authentication.\r\n{}\
             \x1b[0m\r\n",
            creds.host,
            creds.port,
            creds.username,
            creds.auth_method,
            if creds.auth_method == "private_key" {
                "\x1b[33m  • Is the corresponding public key in ~/.ssh/authorized_keys?\r\n\
                 \x1b[33m  • Was the correct private key pasted (not the public key)?\r\n\
                 \x1b[33m  • If the key has a passphrase, is it set correctly?\r\n"
            } else {
                "\x1b[33m  • Is the password correct?\r\n\
                 \x1b[33m  • Does the server allow password authentication?\r\n"
            },
        );
        let _ = output_tx.send(Bytes::from(detail)).await;
        return Err(e);
    }

    let channel = match handle.channel_open_session().await {
        Ok(ch) => ch,
        Err(e) => {
            let msg = format!("\x1b[31mFailed to open channel: {e}\x1b[0m\r\n");
            let _ = output_tx.send(Bytes::from(msg)).await;
            return Err(SshError::Channel(format!("{e}")));
        }
    };

    if let Err(e) = channel.request_pty(false, "xterm-256color", 80, 24, 0, 0, &[]).await {
        let msg = format!("\x1b[31mFailed to request PTY: {e}\x1b[0m\r\n");
        let _ = output_tx.send(Bytes::from(msg)).await;
        return Err(SshError::Channel(format!("PTY: {e}")));
    }

    if let Err(e) = channel.request_shell(false).await {
        let msg = format!("\x1b[31mFailed to request shell: {e}\x1b[0m\r\n");
        let _ = output_tx.send(Bytes::from(msg)).await;
        return Err(SshError::Channel(format!("shell: {e}")));
    }

    // Signal the client that the shell is fully ready.
    let _ = output_tx.send(Bytes::from_static(SSH_READY_MARKER)).await;

    let (mut read_half, write_half) = channel.split();
    let write_half = Arc::new(tokio::sync::Mutex::new(write_half));

    // Send startup command if configured
    if let Some(cmd) = startup_command
        && !cmd.is_empty()
    {
        let cmd_with_newline = format!("{cmd}\n");
        let wh = write_half.lock().await;
        let _ = wh.data(cmd_with_newline.as_bytes()).await;
    }

    // SSH stdout → output_tx
    let read_task = tokio::spawn(async move {
        while let Some(msg) = read_half.wait().await {
            #[allow(clippy::collapsible_match)]
            match msg {
                russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => {
                    if output_tx.send(data).await.is_err() {
                        break;
                    }
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
    });

    // input_rx → SSH stdin / resize
    let recv_task = tokio::spawn(async move {
        while let Some(input) = input_rx.recv().await {
            match input {
                ShellInput::Data(data) => {
                    let wh = write_half.lock().await;
                    if wh.data(&data[..]).await.is_err() {
                        break;
                    }
                }
                ShellInput::Resize { cols, rows } => {
                    let wh = write_half.lock().await;
                    let _ = wh.window_change(cols, rows, 0, 0).await;
                }
            }
        }
    });

    tokio::select! {
        _ = read_task => {}
        _ = recv_task => {}
    }

    tracing::debug!("SSH interactive session ended");
    Ok(())
}
