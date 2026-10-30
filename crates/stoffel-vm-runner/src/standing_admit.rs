//! Admit executions onto a running standing mesh from outside its node processes.
//!
//! A standing node reads its commands from `<control root>/commands/` strictly in
//! sequence (`{sequence:020}.json`) and answers each one with
//! `<control root>/events/party<i>/{sequence:020}.json`. The sequence number is
//! the only thing that orders commands, so two operators that both pick "the next
//! free number" race: the second rename silently replaces the first command, and
//! a command written behind the node's cursor is never read at all.
//!
//! [`StandingAdmitter`] closes both races. Every publisher takes one exclusive
//! lock for the mesh, picks each party's sequence as one past the highest command
//! or event it can see, and publishes with a hard link, which fails instead of
//! replacing a file that already exists. Only publishing is serialized; waiting
//! for the nodes to prepare is not, so admissions from parallel processes still
//! overlap.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use stoffel_vm::net::session::ExecutionId;
use stoffel_vm::net::NodeEventKind;

use crate::standing_control::{
    StandingControlCommandV1, StandingControlOutcomeV1, StandingExecutionAdmissionV1,
};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum StandingAdmitError {
    #[error("standing admission IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not encode standing control command: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("party {party} rejected the command: {error}")]
    Rejected { party: usize, error: String },
    #[error("party {party} reported execution {execution_id} {phase}: {detail}")]
    Lifecycle {
        party: usize,
        execution_id: ExecutionId,
        phase: &'static str,
        detail: String,
    },
    #[error("timed out after {timeout:?} waiting for party {party} to {phase}")]
    Timeout {
        party: usize,
        phase: &'static str,
        timeout: Duration,
    },
}

pub type StandingAdmitResult<T> = Result<T, StandingAdmitError>;

/// How long [`StandingAdmitter::admit`] waits for each stage.
#[derive(Debug, Clone, Copy)]
pub struct AdmitTimeouts {
    /// Until every party has read the command and answered it.
    pub acknowledgement: Duration,
    /// Until every party has prepared the execution: preprocessing reserved and
    /// the execution registered with the coordinator.
    pub ready: Duration,
}

impl Default for AdmitTimeouts {
    fn default() -> Self {
        Self {
            acknowledgement: Duration::from_secs(30),
            ready: Duration::from_secs(120),
        }
    }
}

/// Publishes commands to every party of one standing mesh.
#[derive(Debug, Clone)]
pub struct StandingAdmitter {
    /// One control root per party, indexed by the party's `--party-id`.
    control_roots: Vec<PathBuf>,
    lock_path: PathBuf,
}

impl StandingAdmitter {
    /// `control_roots[i]` is the `--control-dir` of party `i`. Every process that
    /// admits onto the same mesh must use the same `lock_path`.
    pub fn new(control_roots: Vec<PathBuf>, lock_path: impl Into<PathBuf>) -> Self {
        Self {
            control_roots,
            lock_path: lock_path.into(),
        }
    }

    pub fn parties(&self) -> usize {
        self.control_roots.len()
    }

    /// Admit one execution under a fresh identity and wait until every party
    /// has prepared it. On any failure the execution is cancelled on a
    /// best-effort basis before the error is returned.
    pub async fn admit(
        &self,
        program_id: [u8; 32],
        entry: &str,
        clients: Vec<crate::StandingClientAdmissionV1>,
        timeouts: AdmitTimeouts,
    ) -> StandingAdmitResult<ExecutionId> {
        let execution_id = ExecutionId::new();
        let command = StandingControlCommandV1::Prepare {
            admission: StandingExecutionAdmissionV1 {
                execution_id: execution_id.to_string(),
                program_id: hex::encode(program_id),
                entry: entry.to_owned(),
                clients,
            },
        };
        let sequences = self.publish_blocking(command).await?;
        let result = async {
            for (party, outcome) in self
                .wait_for_acknowledgements(&sequences, timeouts.acknowledgement)
                .await?
                .into_iter()
                .enumerate()
            {
                if let StandingControlOutcomeV1::Rejected { error } = outcome {
                    return Err(StandingAdmitError::Rejected { party, error });
                }
            }
            self.wait_until_ready(execution_id, timeouts.ready).await
        }
        .await;
        match result {
            Ok(()) => Ok(execution_id),
            Err(error) => {
                let _ = self.cancel(execution_id, timeouts.acknowledgement).await;
                Err(error)
            }
        }
    }

    /// Cancel an execution on every party and wait for each to acknowledge.
    pub async fn cancel(
        &self,
        execution_id: ExecutionId,
        timeout: Duration,
    ) -> StandingAdmitResult<()> {
        let sequences = self
            .publish_blocking(StandingControlCommandV1::Cancel {
                execution_id: execution_id.to_string(),
            })
            .await?;
        for (party, outcome) in self
            .wait_for_acknowledgements(&sequences, timeout)
            .await?
            .into_iter()
            .enumerate()
        {
            if let StandingControlOutcomeV1::Rejected { error } = outcome {
                return Err(StandingAdmitError::Rejected { party, error });
            }
        }
        Ok(())
    }

    /// Publish one command to every party and return the sequence number it was
    /// published under at each party.
    ///
    /// Blocks while another process holds the mesh's admission lock.
    pub fn publish(&self, command: &StandingControlCommandV1) -> StandingAdmitResult<Vec<u64>> {
        let bytes = serde_json::to_vec(command)?;
        if let Some(parent) = self.lock_path.parent() {
            fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        }
        let lock = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&self.lock_path)
            .map_err(|source| io_error(&self.lock_path, source))?;
        lock.lock()
            .map_err(|source| io_error(&self.lock_path, source))?;

        let mut sequences = Vec::with_capacity(self.control_roots.len());
        for (party, root) in self.control_roots.iter().enumerate() {
            sequences.push(publish_to_party(root, party, &bytes)?);
        }
        // Dropping the file releases the lock.
        drop(lock);
        Ok(sequences)
    }

    async fn publish_blocking(
        &self,
        command: StandingControlCommandV1,
    ) -> StandingAdmitResult<Vec<u64>> {
        let admitter = self.clone();
        tokio::task::spawn_blocking(move || admitter.publish(&command))
            .await
            .expect("standing admission publisher panicked")
    }

    /// Wait until every party has answered the command published under
    /// `sequences` (as returned by [`Self::publish`]).
    pub async fn wait_for_acknowledgements(
        &self,
        sequences: &[u64],
        timeout: Duration,
    ) -> StandingAdmitResult<Vec<StandingControlOutcomeV1>> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut outcomes = Vec::with_capacity(sequences.len());
        for (party, sequence) in sequences.iter().enumerate() {
            let path = self.events_dir(party).join(format!("{sequence:020}.json"));
            let outcome = loop {
                if let Some(outcome) = read_outcome(&path)? {
                    break outcome;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(StandingAdmitError::Timeout {
                        party,
                        phase: "acknowledge the command",
                        timeout,
                    });
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            };
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Wait until every party reports the execution ready, or the first one
    /// reports it failed or cancelled.
    pub async fn wait_until_ready(
        &self,
        execution_id: ExecutionId,
        timeout: Duration,
    ) -> StandingAdmitResult<()> {
        self.wait_for_lifecycle(execution_id, "ready", "prepare the execution", timeout)
            .await
    }

    /// Wait until every party reports the execution completed, or the first
    /// one reports it failed or cancelled.
    pub async fn wait_until_completed(
        &self,
        execution_id: ExecutionId,
        timeout: Duration,
    ) -> StandingAdmitResult<()> {
        self.wait_for_lifecycle(execution_id, "completed", "finish the execution", timeout)
            .await
    }

    async fn wait_for_lifecycle(
        &self,
        execution_id: ExecutionId,
        phase: &'static str,
        doing: &'static str,
        timeout: Duration,
    ) -> StandingAdmitResult<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut pending = (0..self.parties()).collect::<Vec<_>>();
        while !pending.is_empty() {
            let mut still_pending = Vec::with_capacity(pending.len());
            for party in pending {
                let events = self.events_dir(party);
                if events
                    .join(format!("async-{execution_id}-{phase}.json"))
                    .is_file()
                {
                    continue;
                }
                for failure in ["failed", "cancelled"] {
                    let path = events.join(format!("async-{execution_id}-{failure}.json"));
                    if let Some(outcome) = read_outcome(&path)? {
                        return Err(StandingAdmitError::Lifecycle {
                            party,
                            execution_id,
                            phase: failure,
                            detail: outcome_detail(&outcome),
                        });
                    }
                }
                still_pending.push(party);
            }
            pending = still_pending;
            if let Some(&party) = pending.first() {
                if tokio::time::Instant::now() >= deadline {
                    return Err(StandingAdmitError::Timeout {
                        party,
                        phase: doing,
                        timeout,
                    });
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
        Ok(())
    }

    fn events_dir(&self, party: usize) -> PathBuf {
        self.control_roots[party]
            .join("events")
            .join(format!("party{party}"))
    }
}

/// Publish `bytes` as the next command of one party. Callers hold the mesh lock.
fn publish_to_party(root: &Path, party: usize, bytes: &[u8]) -> StandingAdmitResult<u64> {
    let commands = root.join("commands");
    fs::create_dir_all(&commands).map_err(|source| io_error(&commands, source))?;
    let events = root.join("events").join(format!("party{party}"));
    let mut sequence = highest_sequence(&commands)?.max(highest_sequence(&events)?) + 1;

    // The node only reads `{sequence:020}.json`, so the temporary name is never
    // mistaken for a command.
    static NEXT_TEMPORARY: AtomicU64 = AtomicU64::new(0);
    let temporary = commands.join(format!(
        ".admit-{}-{}.tmp",
        std::process::id(),
        NEXT_TEMPORARY.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&temporary, bytes).map_err(|source| io_error(&temporary, source))?;
    let result = loop {
        let path = commands.join(format!("{sequence:020}.json"));
        match fs::hard_link(&temporary, &path) {
            Ok(()) => break Ok(sequence),
            // Someone published without the lock; take the next number rather
            // than overwrite their command.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => sequence += 1,
            Err(source) => break Err(io_error(&path, source)),
        }
    };
    let _ = fs::remove_file(&temporary);
    result
}

/// The highest `{sequence:020}.json` in `directory`, or 0 if there is none.
fn highest_sequence(directory: &Path) -> StandingAdmitResult<u64> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(source) => return Err(io_error(directory, source)),
    };
    let mut highest = 0;
    for entry in entries {
        let path = entry.map_err(|source| io_error(directory, source))?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            if let Some(sequence) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
            {
                highest = highest.max(sequence);
            }
        }
    }
    Ok(highest)
}

/// Read an event file the node may still be writing. Nodes write events with a
/// rename, so a file that exists is complete.
fn read_outcome(path: &Path) -> StandingAdmitResult<Option<StandingControlOutcomeV1>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error(path, source)),
    }
}

fn outcome_detail(outcome: &StandingControlOutcomeV1) -> String {
    match outcome {
        StandingControlOutcomeV1::Rejected { error } => error.clone(),
        StandingControlOutcomeV1::Event { event } => match &event.kind {
            NodeEventKind::Failed { error } => error.clone(),
            other => format!("{other:?}"),
        },
    }
}

fn io_error(path: &Path, source: std::io::Error) -> StandingAdmitError {
    StandingAdmitError::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::standing_control::{
        StandingClientCatalog, StandingExecutionHandler, StandingNodeControl,
        StandingProgramCatalog,
    };
    use crate::ResolvedStandingExecutionAdmissionV1;
    use std::sync::Arc;
    use stoffel_vm::net::{NodeExecutionContext, NodeSupervisor, PreparedNodeExecution};
    use tokio_util::sync::CancellationToken;

    struct NeverPrepares;

    #[async_trait::async_trait]
    impl StandingExecutionHandler for NeverPrepares {
        async fn prepare(
            self: Arc<Self>,
            _admission: ResolvedStandingExecutionAdmissionV1,
            _context: NodeExecutionContext,
        ) -> Result<Box<dyn PreparedNodeExecution>, String> {
            Err("test handler prepares nothing".to_owned())
        }
    }

    /// Run a real control pump for each party, with empty catalogs: every
    /// Prepare is rejected for naming an unknown program, which is enough to
    /// observe how commands are sequenced and acknowledged.
    fn start_parties(
        root: &Path,
        parties: usize,
        cancellation: &CancellationToken,
    ) -> Vec<PathBuf> {
        let programs = Arc::new(StandingProgramCatalog::load(&root.join("programs")).unwrap());
        let clients = Arc::new(StandingClientCatalog::load(&root.join("clients")).unwrap());
        (0..parties)
            .map(|party| {
                let control_root = root.join(format!("node{party}"));
                let (supervisor, events) = NodeSupervisor::new();
                let mut control = StandingNodeControl::new(
                    party,
                    &control_root,
                    Arc::clone(&programs),
                    Arc::clone(&clients),
                    supervisor,
                    events,
                    Arc::new(NeverPrepares),
                )
                .unwrap();
                let cancellation = cancellation.clone();
                tokio::spawn(async move { control.run(cancellation).await.unwrap() });
                control_root
            })
            .collect()
    }

    fn prepare_for(program_id: [u8; 32]) -> StandingControlCommandV1 {
        StandingControlCommandV1::Prepare {
            admission: StandingExecutionAdmissionV1 {
                execution_id: ExecutionId::new().to_string(),
                program_id: hex::encode(program_id),
                entry: "main".to_owned(),
                clients: Vec::new(),
            },
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_publishers_never_lose_or_reorder_a_command() {
        const PARTIES: usize = 3;
        const PUBLISHERS: usize = 24;
        let temporary = tempfile::tempdir().unwrap();
        let cancellation = CancellationToken::new();
        let roots = start_parties(temporary.path(), PARTIES, &cancellation);
        let admitter = StandingAdmitter::new(roots, temporary.path().join("admit.lock"));

        let mut tasks = tokio::task::JoinSet::new();
        for publisher in 0..PUBLISHERS {
            let admitter = admitter.clone();
            tasks.spawn(async move {
                let program_id = [publisher as u8 + 1; 32];
                let sequences = admitter
                    .publish_blocking(prepare_for(program_id))
                    .await
                    .unwrap();
                let outcomes = admitter
                    .wait_for_acknowledgements(&sequences, Duration::from_secs(20))
                    .await
                    .unwrap();
                (program_id, sequences, outcomes)
            });
        }

        let mut seen = vec![Vec::new(); PARTIES];
        while let Some(result) = tasks.join_next().await {
            let (program_id, sequences, outcomes) = result.unwrap();
            for (party, (sequence, outcome)) in sequences.iter().zip(outcomes).enumerate() {
                // The acknowledgement under this publisher's sequence answers
                // this publisher's command, not someone else's.
                match outcome {
                    StandingControlOutcomeV1::Rejected { error } => {
                        assert!(error.contains(&hex::encode(program_id)), "{error}")
                    }
                    other => panic!("unexpected outcome {other:?}"),
                }
                seen[party].push(*sequence);
            }
        }
        for sequences in &mut seen {
            sequences.sort_unstable();
            assert_eq!(*sequences, (1..=PUBLISHERS as u64).collect::<Vec<_>>());
        }
        cancellation.cancel();
    }

    #[tokio::test]
    async fn a_rejected_admission_is_reported_with_its_party() {
        let temporary = tempfile::tempdir().unwrap();
        let cancellation = CancellationToken::new();
        let roots = start_parties(temporary.path(), 2, &cancellation);
        let admitter = StandingAdmitter::new(roots, temporary.path().join("admit.lock"));
        let error = admitter
            .admit([7; 32], "main", Vec::new(), AdmitTimeouts::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&error, StandingAdmitError::Rejected { party: 0, error } if error.contains("not in the standing startup catalog")),
            "{error}"
        );
        cancellation.cancel();
    }

    #[test]
    fn publishing_continues_after_existing_commands_and_events() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("node0");
        let events = root.join("events").join("party0");
        fs::create_dir_all(&events).unwrap();
        fs::create_dir_all(root.join("commands")).unwrap();
        for sequence in 1..=3u64 {
            fs::write(events.join(format!("{sequence:020}.json")), b"{}").unwrap();
        }
        // A command the node has not consumed yet, and stray files it ignores.
        fs::write(root.join("commands").join(format!("{:020}.json", 4)), b"{}").unwrap();
        fs::write(events.join("async-ab-ready.json"), b"{}").unwrap();
        fs::write(events.join(format!("{:020}.tmp", 9)), b"{}").unwrap();

        let admitter = StandingAdmitter::new(vec![root.clone()], temporary.path().join("lock"));
        let sequences = admitter.publish(&prepare_for([1; 32])).unwrap();
        assert_eq!(sequences, vec![5]);
        assert!(root
            .join("commands")
            .join(format!("{:020}.json", 5))
            .is_file());
    }
}
