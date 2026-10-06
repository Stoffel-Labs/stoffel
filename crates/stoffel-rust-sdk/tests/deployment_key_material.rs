//! No image or compose stack of this workspace distributes a private key
//! (`docs/design/bootnode-elimination.md` §9.F.0).
//!
//! Every private key under `ids/` is committed, so the coordinator pin and the
//! node roster authenticate nothing on a port another host can reach. Each
//! Dockerfile and compose file is therefore read line by line — no YAML parser is
//! in the dependency graph — and fails on any of:
//!
//! 1. a Dockerfile that copies `ids`;
//! 2. a compose file that mounts the `ids` directory;
//! 3. a `.der` path in a compose file, outside a comment, anywhere but as the
//!    `file:` of a top-level `secrets:` entry;
//! 4. a published port not bound to `127.0.0.1`, or `network_mode: host`;
//! 5. a service that holds one party's or one client's key and mounts any other
//!    identity's certificate. The coordinator is the only roster authority and
//!    the only place a client is admitted (§9, decisions 1 and 3), so a party is
//!    given the coordinator's certificate and its own and nothing else — no other
//!    node's, no client's — and a client likewise.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Violation {
    DockerfileCopiesIds { line: usize },
    ComposeMountsIds { line: usize },
    PrivateKeyOutsideSecrets { line: usize },
    PortNotLoopback { line: usize },
    HostNetworkMode { line: usize },
    ForeignCertificate { line: usize },
}

/// Whose key a compose service holds, from its `nodeN_key` / `clientN_key`
/// secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Identity {
    Node(u32),
    Client(u32),
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DockerfileCopiesIds { line } => {
                write!(
                    f,
                    "line {line}: the image copies ids/, and with it private keys"
                )
            }
            Self::ComposeMountsIds { line } => {
                write!(
                    f,
                    "line {line}: the ids/ directory, private keys included, is mounted"
                )
            }
            Self::PrivateKeyOutsideSecrets { line } => write!(
                f,
                "line {line}: a .der path outside the file: of a top-level secrets: entry"
            ),
            Self::PortNotLoopback { line } => {
                write!(
                    f,
                    "line {line}: a port published on an interface other than 127.0.0.1"
                )
            }
            Self::HostNetworkMode { line } => {
                write!(
                    f,
                    "line {line}: network_mode: host bypasses loopback-only publishing"
                )
            }
            Self::ForeignCertificate { line } => write!(
                f,
                "line {line}: a party or client is given a certificate other than the \
                 coordinator's and its own"
            ),
        }
    }
}

/// The line without its comment. A `#` starts a comment at the start of the line
/// or after whitespace, which leaves `repo.git#branch` values intact.
fn without_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace()) {
            return &line[..index];
        }
    }
    line
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn unquote(value: &str) -> &str {
    value.trim().trim_matches(|c| c == '"' || c == '\'')
}

fn names_ids_directory(path: &str) -> bool {
    let path = unquote(path).trim_end_matches('/');
    path == "ids" || path.ends_with("/ids")
}

fn dockerfile_violations(text: &str) -> Vec<Violation> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = without_comment(line).trim();
            let mut tokens = line.split_whitespace();
            let instruction = tokens.next()?.to_ascii_uppercase();
            if instruction != "COPY" && instruction != "ADD" {
                return None;
            }
            let tokens: Vec<&str> = tokens.collect();
            // `--from` copies out of another build stage, never out of the context.
            if tokens.iter().any(|token| token.starts_with("--from")) {
                return None;
            }
            let sources: Vec<&str> = tokens
                .into_iter()
                .filter(|token| !token.starts_with("--"))
                .collect();
            let (_destination, sources) = sources.split_last()?;
            sources
                .iter()
                .any(|source| names_ids_directory(source) || unquote(source).starts_with("ids/"))
                .then_some(Violation::DockerfileCopiesIds { line: index + 1 })
        })
        .collect()
}

/// One entry of a `ports:` list: its first line and, for the long form, whether
/// any of its lines binds `host_ip: 127.0.0.1`.
struct PortEntry {
    line: usize,
    short: Option<String>,
    loopback_host_ip: bool,
}

fn compose_violations(text: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut top_level_section = String::new();
    // (indent of the `ports:` key, entries so far)
    let mut ports: Option<(usize, Vec<PortEntry>)> = None;

    let finish_ports = |entries: Vec<PortEntry>, violations: &mut Vec<Violation>| {
        for entry in entries {
            let loopback = match &entry.short {
                Some(short) => unquote(short).starts_with("127.0.0.1:"),
                None => entry.loopback_host_ip,
            };
            if !loopback {
                violations.push(Violation::PortNotLoopback { line: entry.line });
            }
        }
    };

    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = without_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        let indent = indent_of(line);
        let trimmed = line.trim();

        if ports
            .as_ref()
            .is_some_and(|(ports_indent, _)| indent <= *ports_indent)
        {
            let (_, entries) = ports.take().expect("ports section is open");
            finish_ports(entries, &mut violations);
        }
        if let Some((_, entries)) = ports.as_mut() {
            if let Some(item) = trimmed.strip_prefix("- ") {
                let item = item.trim();
                if item.starts_with("target:")
                    || item.starts_with("published:")
                    || item.starts_with("host_ip:")
                    || item.starts_with("protocol:")
                    || item.starts_with("mode:")
                {
                    entries.push(PortEntry {
                        line: number,
                        short: None,
                        loopback_host_ip: item
                            .strip_prefix("host_ip:")
                            .is_some_and(|ip| unquote(ip) == "127.0.0.1"),
                    });
                } else {
                    entries.push(PortEntry {
                        line: number,
                        short: Some(item.to_owned()),
                        loopback_host_ip: false,
                    });
                }
            } else if let Some(ip) = trimmed.strip_prefix("host_ip:") {
                if let Some(entry) = entries.last_mut() {
                    entry.loopback_host_ip |= unquote(ip) == "127.0.0.1";
                }
            }
        }

        if indent == 0 {
            top_level_section = trimmed
                .split_once(':')
                .map_or(trimmed, |(name, _)| name)
                .to_owned();
        }

        if let Some(value) = trimmed.strip_prefix("ports:") {
            let value = value.trim();
            if value.is_empty() {
                ports = Some((indent, Vec::new()));
            } else {
                let items = value.trim_start_matches('[').trim_end_matches(']');
                let entries = items
                    .split(',')
                    .filter(|item| !item.trim().is_empty())
                    .map(|item| PortEntry {
                        line: number,
                        short: Some(item.trim().to_owned()),
                        loopback_host_ip: false,
                    })
                    .collect();
                finish_ports(entries, &mut violations);
            }
        }

        if trimmed
            .strip_prefix("network_mode:")
            .is_some_and(|mode| unquote(mode) == "host")
        {
            violations.push(Violation::HostNetworkMode { line: number });
        }

        // Short volume syntax `<source>:<target>[:mode]`, and the long form's
        // `source:`.
        let mount_source = trimmed
            .strip_prefix("- ")
            .map(unquote)
            .and_then(|volume| volume.find(":/").map(|end| &volume[..end]))
            .or_else(|| trimmed.strip_prefix("source:").map(unquote));
        if mount_source.is_some_and(names_ids_directory) {
            violations.push(Violation::ComposeMountsIds { line: number });
        }

        if trimmed.contains(".der") {
            let secret_file =
                top_level_section == "secrets" && indent > 0 && trimmed.starts_with("file:");
            if !secret_file {
                violations.push(Violation::PrivateKeyOutsideSecrets { line: number });
            }
        }
    }
    if let Some((_, entries)) = ports.take() {
        finish_ports(entries, &mut violations);
    }
    violations
}

/// Every `<prefix><digits><suffix>` in `line`, by its number.
fn numbered(line: &str, prefix: &str, suffix: &str) -> Vec<u32> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find(prefix) {
        let after = &rest[start + prefix.len()..];
        let digits = after.len() - after.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if digits > 0 && after[digits..].starts_with(suffix) {
            if let Ok(number) = after[..digits].parse() {
                found.push(number);
            }
        }
        rest = after;
    }
    found
}

/// The identities whose key a line names (`node0_key`, `client1_key`).
fn keys_named(line: &str) -> Vec<Identity> {
    numbered(line, "node", "_key")
        .into_iter()
        .map(Identity::Node)
        .chain(
            numbered(line, "client", "_key")
                .into_iter()
                .map(Identity::Client),
        )
        .collect()
}

/// The identities whose certificate a line names, as a compose config
/// (`node0_cert`) or as a mounted path (`/app/ids/clients/cert1.crt`).
fn certificates_named(line: &str) -> Vec<Identity> {
    numbered(line, "node", "_cert")
        .into_iter()
        .chain(numbered(line, "/ids/nodes/cert", ".crt"))
        .map(Identity::Node)
        .chain(
            numbered(line, "client", "_cert")
                .into_iter()
                .chain(numbered(line, "/ids/clients/cert", ".crt"))
                .map(Identity::Client),
        )
        .collect()
}

/// Check 5: within `services:`, a service that holds exactly one party's or
/// client's key names no other identity's certificate, and does not take its
/// certificate list from an alias this check cannot see through.
fn foreign_certificate_violations(text: &str) -> Vec<Violation> {
    // (line number, line without comment) of the service being read.
    let mut service: Vec<(usize, String)> = Vec::new();
    let mut violations = Vec::new();
    let mut in_services = false;

    let finish = |service: &mut Vec<(usize, String)>, violations: &mut Vec<Violation>| {
        let keys: BTreeSet<Identity> = service
            .iter()
            .flat_map(|(_, line)| keys_named(line))
            .collect();
        if keys.len() == 1 {
            let own = *keys.iter().next().expect("one key");
            for (number, line) in service.iter() {
                // A whole `configs:` list taken from an alias cannot be read
                // line by line, so it is refused rather than trusted: a party
                // or client spells out the certificates it is given.
                let foreign = certificates_named(line)
                    .into_iter()
                    .any(|identity| identity != own)
                    || line.trim().starts_with("configs: *");
                if foreign {
                    violations.push(Violation::ForeignCertificate { line: *number });
                }
            }
        }
        service.clear();
    };

    for (index, raw) in text.lines().enumerate() {
        let line = without_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        let indent = indent_of(line);
        if indent == 0 {
            finish(&mut service, &mut violations);
            in_services = line.trim_end() == "services:";
            continue;
        }
        if !in_services {
            continue;
        }
        if indent == 2 {
            finish(&mut service, &mut violations);
        }
        service.push((index + 1, line.to_owned()));
    }
    finish(&mut service, &mut violations);
    violations
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn files_in(dir: &Path, matches: impl Fn(&str) -> bool) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(&matches)
        })
        .collect();
    files.sort();
    files
}

#[test]
fn no_image_or_stack_distributes_a_private_key() {
    let root = workspace_root();
    let dockerfiles: Vec<PathBuf> = files_in(&root, |name| name.starts_with("Dockerfile"))
        .into_iter()
        .chain(files_in(&root.join("docker"), |name| {
            name.ends_with(".Dockerfile")
        }))
        .collect();
    let compose_files: Vec<PathBuf> = files_in(&root, |name| {
        name.starts_with("docker-compose") && name.ends_with(".yml")
    })
    .into_iter()
    .chain(files_in(
        &root.join("crates/stoffel-lang/examples"),
        |name| name.ends_with(".yml"),
    ))
    .collect();
    assert!(
        dockerfiles.len() >= 3,
        "expected the workspace's Dockerfiles, found {dockerfiles:?}"
    );
    assert!(
        compose_files.len() >= 8,
        "expected the workspace's compose files, found {compose_files:?}"
    );

    let mut failures = Vec::new();
    for (files, check) in [
        (
            &dockerfiles,
            dockerfile_violations as fn(&str) -> Vec<Violation>,
        ),
        (&compose_files, compose_violations),
        (&compose_files, foreign_certificate_violations),
    ] {
        for path in files {
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            for violation in check(&text) {
                failures.push(format!("{}: {violation}", path.display()));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn each_check_fails_on_a_line_that_breaks_it() {
    assert_eq!(
        dockerfile_violations("FROM scratch\n# COPY ids /app/ids\nCOPY ids /app/ids\n"),
        vec![Violation::DockerfileCopiesIds { line: 3 }]
    );
    assert_eq!(
        dockerfile_violations("COPY --chown=app ./ids/ /app/ids\nADD ids/nodes /app/n\n"),
        vec![
            Violation::DockerfileCopiesIds { line: 1 },
            Violation::DockerfileCopiesIds { line: 2 },
        ]
    );
    assert!(dockerfile_violations("COPY --from=builder /build/ids /app/x\n").is_empty());

    let mounts = "\
services:
  a:
    volumes:
      - ./ids:/app/ids:ro
      - ${STOFFEL_VM_DIR:-../../..}/ids:/app/ids:ro
      - type: bind
        source: ./ids
        target: /app/ids
      - stoffel-store:/app/store
";
    assert_eq!(
        compose_violations(mounts),
        vec![
            Violation::ComposeMountsIds { line: 4 },
            Violation::ComposeMountsIds { line: 5 },
            Violation::ComposeMountsIds { line: 7 },
        ]
    );

    let keys = "\
services:
  a:
    environment:
      STOFFEL_KEY: /app/ids/nodes/key0.der
      # STOFFEL_KEY: /app/ids/nodes/key1.der
    secrets:
      - node0_key
secrets:
  node0_key:
    file: ./ids/nodes/key0.der
configs:
  node0_cert:
    file: ./ids/nodes/key0.der
";
    assert_eq!(
        compose_violations(keys),
        vec![
            Violation::PrivateKeyOutsideSecrets { line: 4 },
            Violation::PrivateKeyOutsideSecrets { line: 13 },
        ]
    );

    let published = "\
services:
  a:
    ports:
      - \"9000:9000\"
      - \"127.0.0.1:9001:9001/udp\"
      - \"9002\"
      - target: 9003
        published: \"9003\"
      - target: 9004
        published: \"9004\"
        host_ip: 127.0.0.1
    healthcheck:
      test: [\"CMD\", \"true\"]
  b:
    network_mode: host
    ports: [\"9005:9005\", \"127.0.0.1:9006:9006\"]
";
    let identities = "\
x-coordinator-certificates: &coordinator-certificates
  - source: node0_cert
  - source: client0_cert
services:
  coordinator:
    configs: *coordinator-certificates
    secrets:
      - coordinator_key
  party0:
    configs:
      - source: coordinator_cert
      - source: node0_cert
        target: /app/ids/nodes/cert0.crt
      - source: client0_cert
    secrets:
      - node0_key
    environment:
      STOFFEL_CERT: /app/ids/nodes/cert1.crt
  party1:
    configs: *certificates
    secrets: [node1_key]
  client0:
    configs:
      - source: client0_cert
      - source: node2_cert
    secrets:
      - client0_key
    environment:
      STOFFEL_CERT: /app/ids/clients/cert0.crt
";
    assert_eq!(
        foreign_certificate_violations(identities),
        vec![
            Violation::ForeignCertificate { line: 14 },
            Violation::ForeignCertificate { line: 18 },
            Violation::ForeignCertificate { line: 20 },
            Violation::ForeignCertificate { line: 25 },
        ]
    );

    assert_eq!(
        compose_violations(published),
        vec![
            Violation::PortNotLoopback { line: 4 },
            Violation::PortNotLoopback { line: 6 },
            Violation::PortNotLoopback { line: 7 },
            Violation::HostNetworkMode { line: 15 },
            Violation::PortNotLoopback { line: 16 },
        ]
    );
}
