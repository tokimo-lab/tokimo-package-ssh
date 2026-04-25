# tokimo-package-ssh

SSH client for Tokimo: terminal sessions, shell execution, and file transfer (SFTP upload/download/mkdir/list).

## Features

- **Interactive shell sessions** — open SSH sessions with a ready-marker protocol for pseudo-terminal management
- **Command execution** — run commands and collect output (`exec`, `exec_stream` for streaming output)
- **File transfer** — upload/download streams, list directories recursively, create directories
- **Docker-over-SSH** — list containers and volumes on remote hosts
- **Network utilities** — port scan, traceroute
- **System info** — fetch OS details, disk usage, running processes
- **Shell escaping** — safe `shell_escape` for building remote commands

## Usage

```rust
use tokimo_package_ssh::{SshCredentials, client, files};

let creds = SshCredentials {
    host: "example.com".into(),
    port: 22,
    username: "user".into(),
    password: Some("pass".into()),
    ..Default::default()
};

// Execute a command
let output = client::exec(&creds, "ls /tmp").await?;

// List directory recursively
let entries = files::list_dir_recursive(&creds, "/data").await?;

// Upload a stream
let (tx, rx) = tokio::sync::mpsc::channel(16);
files::upload_stream(&creds, "/remote/path/file.bin", rx).await?;
```

## Cargo

```toml
tokimo-package-ssh = { git = "https://github.com/tokimo-lab/tokimo-package-ssh" }
```

## License

MIT
