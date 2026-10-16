#!/usr/bin/env python3
"""Docker acceptance for the concurrent, long-running standing node.

The driver intentionally checks public behavior: immutable admissions, client
results, concurrent intervals, cooperative scheduling, restart recovery, and
bounded mesh faults. Protocol/store unit tests own internal data structures and
log formatting.

The driver is an *operator* of the coordinator, not a writer of a directory the
nodes have mounted. It holds one of the certificates the coordinator was started
with in `--operator-certs`, submits each execution over that authenticated link,
and the coordinator mints the identity and publishes the execution down to the
roster on `sub_executions`. So the driver never chooses an execution identity and
never tells a node anything: it learns each identity from what the coordinator
minted, and it observes the nodes through their own logs.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator


PARTIES = [f"party{party}" for party in range(5)]
NODE_RPC_SERVERS = ",".join(
    f"172.33.0.{party + 10}:16180" for party in range(5)
)
# The client-facing listener, which is a different socket from the mesh bind on
# purpose: the mesh admits exactly the coordinator's node roster, while this one
# authorizes no certificate at the transport, so that no client key acquires
# node-level standing and the coordinator's per-execution admissions are the
# whole of client authorization (design doc section 9 rule 3). Those admissions
# decide this socket twice over: who may hold a connection at all, and which
# execution a frame may reach. Every node advertises exactly the port it binds,
# and every party is symmetric: no party's port is offset from the port it
# listens on.
NODE_CLIENT_TRANSPORT_SERVERS = ",".join(
    f"172.33.0.{party + 10}:{9100 + party}" for party in range(5)
)
COORDINATOR = "coordinator:31415"
# The coordinator is the roster authority, so every connection to it pins the key
# of this certificate; an unpinned connection accepts whoever answers at the port.
COORDINATOR_CERT = "/app/ids/server_cert.crt"
# The operator identity. Only the key the coordinator pinned in --operator-certs
# can submit or abort an execution, so this is the whole authorization boundary
# that the mounted command directory used to be.
OPERATOR_CERT = "/app/ids/operator/cert.crt"
OPERATOR_KEY = "/run/secrets/stoffel_operator.key"
# A matched identity the coordinator never listed as an operator, so a refusal
# of it comes from the coordinator and not from a local TLS key mismatch.
NON_OPERATOR_CERT = "/run/secrets/stoffel_nonoperator.crt"
NON_OPERATOR_KEY = "/run/secrets/stoffel_nonoperator.key"
# The client certificates the nodes hold, mounted identically into the operator
# so that the name the operator submits and the certificate a node resolves it
# to are the same file.
CLIENT_CERT_DIR = "/var/lib/stoffel/client-certs"
HEX_ID = re.compile(r"^[0-9a-f]{64}$")
# The adversarial side of the client-facing listener. Nothing in a deployment
# runs it; it exists because that listener authorizes no certificate, so the
# only way to test its refusals is to dial it directly rather than through the
# coordinator the way every client in this campaign does.
CLIENT_LISTENER_PROBE = "/app/stoffel-client-listener-probe"
# What a node says when the per-execution client roster — which is the whole of
# client authorization on that listener — refuses a route. The cause is in the
# error field, not the message, so this asserts the specific one: a certificate
# the execution does not name, and not a route conflict or an unreadable
# certificate, which are different refusals with the same message.
CLIENT_ROUTE_REFUSED = re.compile(
    r"refusing a client execution route"
    r".*execution_id=(?P<execution>[0-9a-f]{64})"
    r".*error=certificate is not authorized for execution (?P<refused>[0-9a-f]{64})"
)
# What a node says when `ClientIngressGate` refuses a connection because the
# listener is already as occupied as it is allowed to be.
CLIENT_INGRESS_REFUSED = re.compile(
    r"client-facing listener refused connections"
    r".*refused_over_capacity=(?P<over_capacity>\d+)"
)
# And what it says when it refuses one because the coordinator has admitted that
# certificate on no execution here, which is the listener's first question and a
# different refusal from running out of room.
CLIENT_INGRESS_UNADMITTED = re.compile(
    r"client-facing listener refused connections"
    r".*refused_unadmitted_certificate=(?P<unadmitted>\d+)"
)
# How many handshakes the flood probe actually got through, which is the number
# of refusals a party then owes an operator: a dial that never reached the
# handshake never reached the gate either.
PROBE_FLOOD_HANDSHAKES = re.compile(
    r"probe: flood completed (?P<completed>\d+)/(?P<attempted>\d+) handshakes"
)

# What a standing node says about each execution it is told to run. These lines
# are the node's observable lifecycle; there is no acknowledgement file to read
# because there is no command file to acknowledge.
NODE_EVENT = re.compile(
    r"\[party \d+\] execution (?P<execution>[0-9a-f]{64}) "
    r"(?P<phase>preparing|ready|cancellation accepted|cancelled|completed|failed"
    r"|is already running|is not running here"
    r"|was already admitted by this node)"
    r"(?P<detail>.*)$"
)
# The line a standing node prints once per process, before it has read anything
# off the coordinator's stream. `admitted_identities` is the size of the durable
# admission index as the process reopened it, so it is zero on a fresh index and
# carries the whole history of the deployment on a retained one. That is the one
# number a restart arm can read to tell the two apart.
NODE_READY_MARKER = "standing node ready:"
NODE_READY = re.compile(
    r"\[party \d+\] standing node ready:.*admitted_identities=(?P<identities>\d+)"
)
NODE_REFUSED = re.compile(
    r"\[party \d+\] refusing execution (?P<execution>[0-9a-f]{64}): (?P<error>.*)$"
)
# Both campaigns' program catalogs hold a HoneyBadger artifact and an AVSS one,
# and both are meant to. `assert_reservoir_backends` turns that intent into a
# measurement against what the nodes actually warmed.
STANDING_BACKENDS = {"honeybadger", "avss"}
LOG_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)")
# `tracing_subscriber::fmt` styles its field names and separators even when its
# writer is not a terminal, so a `tracing`-emitted field reads as
# `\x1b[3mname\x1b[0m\x1b[2m=\x1b[0mvalue` in captured output. `docker compose
# logs --no-color` suppresses Compose's own colour, not the node's, so field
# matching has to see through it. Every other marker here matches a plain
# `println!` line and is unaffected.
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
YIELD_COUNTS = re.compile(
    r"instruction_budget_yields=(?P<instruction>\d+) online_effect_yields=(?P<online>\d+)"
)
# The phases the node prints, mapped onto the names the campaign asserts on.
PHASE_NAMES = {
    "cancellation accepted": "cancel_accepted",
    "is already running": "already_running",
    "is not running here": "not_running",
    "was already admitted by this node": "already_admitted",
}


class AcceptanceFailure(RuntimeError):
    pass


@dataclass
class ClientJob:
    label: str
    container: str
    process: subprocess.Popen[str]
    stream: Any
    log: Path
    expected: list[int]
    outputs: int


def yield_counts(event: dict[str, Any]) -> dict[str, int]:
    """The cooperative-yield counters a completed execution reported.

    They are the only evidence that an execution shared its process rather than
    monopolising it, so a completion line without them is a failure rather than
    a zero.
    """
    match = YIELD_COUNTS.search(str(event.get("detail", "")))
    if match is None:
        raise AcceptanceFailure(
            f"completion for {event.get('execution_id')} reported no yield counters: {event}"
        )
    return {
        "instruction_budget_yields": int(match.group("instruction")),
        "online_effect_yields": int(match.group("online")),
    }


def log_timestamp_ns(value: str) -> int:
    """A docker log timestamp as nanoseconds, for the concurrency interval proof."""
    whole, _, fraction = value.rstrip("Z").partition(".")
    seconds = int(
        time.mktime(time.strptime(whole, "%Y-%m-%dT%H:%M:%S"))
    )
    return seconds * 1_000_000_000 + int(f"{fraction:<09s}"[:9])


def execution_id(number: int) -> str:
    return f"{number:064x}"


class Harness:
    def __init__(self, campaign: str) -> None:
        self.campaign = campaign
        self.root = Path(__file__).resolve().parents[2]
        self.compose_file = self.root / "docker-compose.standing-concurrency.yml"
        self.project = os.environ.get("PROJECT_NAME", f"stoffel-standing-{campaign}")
        self.wait_seconds = int(os.environ.get("WAIT_TIMEOUT_SECS", "900"))
        default_coordination = "120" if campaign == "concurrency" else "30"
        default_protocol = "600" if campaign == "concurrency" else "45"
        self.coordination_seconds = int(
            os.environ.get("COORDINATION_TIMEOUT_SECS", default_coordination)
        )
        self.protocol_seconds = int(
            os.environ.get("PROTOCOL_TIMEOUT_SECS", default_protocol)
        )
        configured_state = os.environ.get("STOFFEL_STANDING_STATE_DIR")
        self.state = (
            Path(configured_state)
            if configured_state
            else Path(tempfile.mkdtemp(prefix=f"stoffel-standing-{campaign}."))
        )
        pool_id = os.environ.get("STOFFEL_STANDING_POOL_ID") or hashlib.sha256(
            b"stoffel-standing-compose-pool-v1\0"
            + self.project.encode()
            + b"\0"
            + str(self.state.resolve()).encode()
        ).hexdigest()
        if not HEX_ID.fullmatch(pool_id) or int(pool_id, 16) == 0:
            raise AcceptanceFailure("STOFFEL_STANDING_POOL_ID must be nonzero 64-hex")
        self.keep_state = os.environ.get("STOFFEL_KEEP_STANDING_STATE", "0") == "1"
        self.image = os.environ.get(
            "STOFFEL_STANDING_NODE_IMAGE", "stoffel-standing-node:local"
        )
        self.env = os.environ.copy()
        self.manages_client_certificates = "STOFFEL_STANDING_CLIENT_CERTS_DIR" not in self.env
        if self.manages_client_certificates:
            self.env["STOFFEL_STANDING_CLIENT_CERTS_DIR"] = str(
                (self.state / "client-certificates").resolve()
            )
        self.env.update(
            {
                "STOFFEL_STANDING_STATE_DIR": str(self.state),
                "STOFFEL_STANDING_POOL_ID": pool_id,
                "STOFFEL_EXECUTION_COORDINATION_TIMEOUT_SECONDS": str(
                    self.coordination_seconds
                ),
                "STOFFEL_MPC_PROTOCOL_TIMEOUT_SECONDS": str(self.protocol_seconds),
                # Every readiness check and most assertions in this campaign
                # read container logs, so the logs must not roll over: the MPC
                # libraries log one line per protocol message, which at the
                # campaign's preprocessing sizes pushes a node's whole startup
                # — the catalog it froze and the reservoirs it warmed — out of
                # the retained window within a minute, and `start_nodes` then
                # waits for markers that were printed and lost. The node's own
                # lines stay at `info`; the per-message chatter underneath them
                # does not. Override with STOFFEL_ACCEPTANCE_RUST_LOG when
                # debugging the protocol itself.
                "RUST_LOG": os.environ.get(
                    "STOFFEL_ACCEPTANCE_RUST_LOG",
                    "info,stoffelcrypto=warn,stoffelmpc=warn,stoffelnet=warn",
                ),
            }
        )
        self.paused: set[str] = set()
        self.client_jobs: list[ClientJob] = []
        self.network = ""
        self.programs: dict[str, str] = {}
        self.allocation_digests: dict[str, str] = {}
        # Every identity this deployment has watched all five parties admit.
        # The restart arm asserts the reopened admission index is at least this
        # large, so it has to be the campaign's own record rather than anything
        # scraped back out of the logs it is checking.
        self.admitted_identities: set[str] = set()

    def command(
        self,
        args: list[str],
        *,
        check: bool = True,
        capture: bool = False,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            args,
            cwd=self.root,
            env=self.env,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            output = f"\n{result.stdout}" if capture and result.stdout else ""
            raise AcceptanceFailure(
                f"command failed ({result.returncode}): {' '.join(args)}{output}"
            )
        return result

    def compose_args(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "--project-name",
            self.project,
            "--file",
            str(self.compose_file),
            *args,
        ]

    def compose(self, *args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return self.command(self.compose_args(*args), **kwargs)

    def logs(
        self,
        party: str | None = None,
        tail: int | None = None,
        timestamps: bool = False,
    ) -> str:
        args = ["logs", "--no-color"]
        if timestamps:
            args.append("--timestamps")
        if tail is not None:
            args.extend(["--tail", str(tail)])
        args.extend([party] if party else [*PARTIES, "coordinator"])
        captured = self.compose(*args, check=False, capture=True).stdout or ""
        return ANSI_ESCAPE.sub("", captured)

    def require_source(self, variable: str, marker: str, *, require_git: bool) -> Path:
        raw = self.env.get(variable, "")
        path = Path(raw)
        if not path.is_absolute() or not path.is_dir() or not (path / marker).is_file():
            raise AcceptanceFailure(
                f"{variable} must be an absolute source tree containing {marker}"
            )
        if require_git:
            result = self.command(
                ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
                check=False,
                capture=True,
            )
            if result.returncode != 0:
                raise AcceptanceFailure(f"{variable} must be a Git checkout")
        resolved = path.resolve()
        self.env[variable] = str(resolved)
        return resolved

    def initialize(self, fixtures: dict[str, str]) -> None:
        for tool in ("docker", "git"):
            if shutil.which(tool) is None:
                raise AcceptanceFailure(f"required tool not found: {tool}")
        coordinator = self.require_source(
            "STOFFEL_COORDINATOR_CONTEXT",
            "crates/off-chain/Cargo.toml",
            require_git=True,
        )
        networking = self.require_source(
            "STOFFEL_NETWORK_CONTEXT", "Cargo.toml", require_git=True
        )
        if self.coordination_seconds < 8:
            raise AcceptanceFailure("COORDINATION_TIMEOUT_SECS must be at least 8")

        self.compose(
            "--profile", "tools", "down", "--remove-orphans", "--volumes", check=False
        )
        if self.manages_client_certificates:
            client_certificates = Path(self.env["STOFFEL_STANDING_CLIENT_CERTS_DIR"])
            client_certificates.mkdir(parents=True, exist_ok=True)
            for certificate in sorted((self.root / "ids" / "clients").glob("*.crt")):
                shutil.copy2(certificate, client_certificates / certificate.name)
        (self.state / "programs").mkdir(parents=True, exist_ok=True)
        (self.state / "logs").mkdir(parents=True, exist_ok=True)
        print(
            "== Building the exact VM, coordinator, and networking worktrees ==",
            flush=True,
        )
        self.compose("--profile", "tools", "build")
        self.command(["docker", "image", "inspect", self.image], capture=True)
        self.record_provenance(coordinator, networking)
        self.assert_credentials()
        for name, fixture in fixtures.items():
            self.programs[name] = self.install_artifact(fixture)
        self.assert_programs_are_visible()
        self.compose("--profile", "tools", "config", capture=True)

    def assert_programs_are_visible(self) -> None:
        """Wait until a container reading the programs mount sees every artifact.

        Each artifact is copied into the shared programs directory by a one-off
        container, and a standing node reads that directory exactly once, at
        startup, because its catalog is frozen there. On a host whose bind mount
        is not immediately coherent between containers a node can load a short
        catalog, warm fewer reservoirs than the campaign installed programs for,
        and then idle forever while `start_nodes` waits for reservoirs that will
        never be warmed — a failure that looks like a node bug and is not one.
        Reading the mount from the node image until it agrees with what was
        installed turns that into a wait here.
        """
        expected = {f"{program}.stflb" for program in self.programs.values()}
        deadline = time.monotonic() + max(30, self.coordination_seconds)
        observed: set[str] = set()
        while time.monotonic() < deadline:
            listing = self.command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "/bin/sh",
                    "--volume",
                    f"{self.state / 'programs'}:/programs:ro",
                    self.image,
                    "-ec",
                    "ls /programs",
                ],
                capture=True,
            ).stdout
            observed = {line.strip() for line in listing.splitlines() if line.strip()}
            if expected <= observed:
                print(
                    f"The programs mount shows all {len(expected)} installed artifacts.",
                    flush=True,
                )
                return
            time.sleep(1)
        raise AcceptanceFailure(
            "the programs mount never showed every installed artifact to a container: "
            f"missing {sorted(expected - observed)}"
        )

    def record_provenance(self, coordinator: Path, networking: Path) -> None:
        lines = []
        for label, path in (
            ("vm", self.root),
            ("coordinator", coordinator),
            ("networking", networking),
        ):
            git_root = self.command(
                ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                capture=True,
                check=False,
            )
            is_checkout_root = git_root.returncode == 0 and Path(
                git_root.stdout.strip()
            ).resolve() == path.resolve()
            if is_checkout_root:
                head = self.command(
                    ["git", "-C", str(path), "rev-parse", "HEAD"], capture=True
                ).stdout.strip()
                status = self.command(
                    ["git", "-C", str(path), "status", "--short"], capture=True
                ).stdout.rstrip()
            else:
                digest = hashlib.sha256()
                for source in sorted(item for item in path.rglob("*") if item.is_file()):
                    relative = source.relative_to(path)
                    if "target" in relative.parts:
                        continue
                    digest.update(str(relative).encode())
                    digest.update(b"\0")
                    digest.update(source.read_bytes())
                head = f"vendored-sha256:{digest.hexdigest()}"
                status = ""
            lines.extend([f"{label}_context={path}", f"{label}_head={head}", status])
        image = self.command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", self.image],
            capture=True,
        ).stdout.strip()
        lines.append(f"image_id={image}")
        (self.state / "logs" / "build-provenance.txt").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

    def assert_credentials(self) -> None:
        public_only = r"""
unexpected="$(find /app/ids -type f ! -name '*.crt' -print)"
test -z "$unexpected"
test -r /app/ids/server_cert.crt
for n in 0 1 2 3 4; do test -r "/app/ids/nodes/cert${n}.crt"; done
for n in 0 1; do test -r "/app/ids/clients/cert${n}.crt"; done
"""
        self.command(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "/bin/sh",
                self.image,
                "-ec",
                public_only,
            ]
        )

        isolated = r"""
cert=/run/secrets/stoffel_identity.crt
key=/run/secrets/stoffel_identity.key
test "$(find /run/secrets -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 2
test "$(sha256sum "$cert" | cut -d ' ' -f 1)" = "$EXPECTED_CERT"
test "$(sha256sum "$key" | cut -d ' ' -f 1)" = "$EXPECTED_KEY"
test -z "$(find /app /run/secrets -type f \( -name '*.der' -o -name '*.key' \) ! -path "$key" -print)"
"""
        credentials = [
            *[
                (
                    f"party{slot}",
                    self.root / f"ids/nodes/cert{slot}.crt",
                    self.root / f"ids/nodes/key{slot}.der",
                )
                for slot in range(5)
            ],
            *[
                (
                    f"client{slot}",
                    self.root / f"ids/clients/cert{slot}.crt",
                    self.root / f"ids/clients/key{slot}.der",
                )
                for slot in range(2)
            ],
        ]
        for service, cert, key in credentials:
            cert_hash = hashlib.sha256(cert.read_bytes()).hexdigest()
            key_hash = hashlib.sha256(key.read_bytes()).hexdigest()
            self.compose(
                "--profile",
                "tools",
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "--env",
                f"EXPECTED_CERT={cert_hash}",
                "--env",
                f"EXPECTED_KEY={key_hash}",
                "--entrypoint",
                "/bin/sh",
                service,
                "-ec",
                isolated,
            )

    def install_artifact(self, fixture: str) -> str:
        output = self.command(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "/app/stoffel-run",
                self.image,
                "--print-program-id",
                fixture,
            ],
            capture=True,
        ).stdout
        matches = re.findall(r"[0-9a-f]{64}", output)
        if not matches:
            raise AcceptanceFailure(f"could not derive program ID for {fixture}")
        program = matches[-1]
        # The artifact is written to the shared programs directory by *this*
        # process, not by a container with the directory bind-mounted into it.
        # A standing node reads that directory once, at startup, because its
        # catalog is frozen there, and a container's write to a bind mount is
        # not reliably visible to another container that mounts the same host
        # path moments later: nodes were observed freezing catalogs of two and
        # of one artifact out of five that were already on disk, warming only
        # those reservoirs and then idling while `start_nodes` waited for the
        # rest. Writing from the host makes the host filesystem the only writer,
        # which is what `all_examples.py` has always done by compiling there.
        artifact = self.state / "programs" / f"{program}.stflb"
        temporary = artifact.with_suffix(".stflb.partial")
        with temporary.open("wb") as handle:
            extracted = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "/bin/cat",
                    self.image,
                    fixture,
                ],
                cwd=self.root,
                env=self.env,
                check=False,
                stdout=handle,
                stderr=subprocess.PIPE,
                text=False,
            )
        if extracted.returncode != 0:
            temporary.unlink(missing_ok=True)
            raise AcceptanceFailure(
                f"could not read {fixture} out of {self.image}: "
                f"{(extracted.stderr or b'').decode(errors='replace')}"
            )
        # One atomic rename, so a node can never read a half-written artifact
        # and refuse it for not matching its own content address.
        temporary.replace(artifact)
        return program

    def marker_count(self, party: str, marker: str) -> int:
        return self.logs(party).count(marker)

    def reservoir_rebuild_count(self, party: str) -> int:
        return sum(
            "standing preprocessing agreement:" in line
            and "action=Rebuild" in line
            for line in self.logs(party).splitlines()
        )

    def agreement_action_counts(self, party: str, backend: str) -> dict[str, int]:
        """How many times `party` agreed each plan for `backend`'s reservoirs.

        The line is `[party N] <BACKEND> standing preprocessing agreement:
        action=... generation=... targets=...`, and it carries no `program=`
        field, so this is per backend and not per program. That is enough here
        because the concurrency catalog holds exactly one AVSS program.

        This couples to a log phrase, which `docker/preproc-log-markers.sh`
        exists to avoid doing. The coupling is accepted rather than overlooked:
        the agreement line has no marker constant to read (the three that do
        are the preprocessing-store markers), `reservoir_rebuild_count`
        immediately above already depends on the same two substrings, and the
        alternative is a change to crates/stoffel-vm-runner, which this harness
        does not own. If that line ever gains a `program=` field or a marker
        constant, both of these should move onto it.
        """
        counts: dict[str, int] = {}
        marker = f"{backend} standing preprocessing agreement:"
        for line in self.logs(party).splitlines():
            if marker not in line:
                continue
            if match := re.search(r"\baction=(\w+)", line):
                counts[match.group(1)] = counts.get(match.group(1), 0) + 1
        return counts

    def agreement_action_baseline(self, backend: str) -> dict[str, dict[str, int]]:
        return {
            party: self.agreement_action_counts(party, backend) for party in PARTIES
        }

    def assert_agreement_actions(
        self,
        backend: str,
        baseline: dict[str, dict[str, int]],
        expected: dict[str, int],
    ) -> None:
        """Pin which preprocessing plan each party agreed for one backend.

        `start_nodes(expected_rebuild=...)` already pins the number of REBUILDS,
        across all backends together. What it cannot see is the difference
        between the two non-rebuild plans, and that difference is the whole
        subject here: `Reuse` keeps an existing pool untouched, while `TopUp`
        enters `top_up_exact` on a reservoir that is NOT empty — the one path
        where the landed pool-clear (design doc §9.1 stage A2) meets inherited
        material. Whether AVSS reaches it depends on arithmetic nothing asserts:
        the restart re-warms every catalog program to `per_execution x
        (burst_capacity + 1)`, so an AVSS scope that happens to be full enough
        would agree `Reuse` and this campaign's only AVSS partial refill would
        disappear with every other assertion still passing.

        The counts are deltas against a baseline because the containers keep
        their predecessor's log across a restart.
        """
        for party in PARTIES:
            observed = {
                action: count - baseline[party].get(action, 0)
                for action, count in self.agreement_action_counts(
                    party, backend
                ).items()
            }
            observed = {action: delta for action, delta in observed.items() if delta}
            if observed != expected:
                raise AcceptanceFailure(
                    f"{party} agreed {backend} preprocessing plans {observed}; "
                    f"expected exactly {expected}. A plan that silently changed "
                    "retires this campaign's coverage of the arm it names "
                    "without failing any other assertion."
                )

    def start_nodes(
        self,
        expected_programs: int,
        expected_rebuild: bool | None = None,
        expected_backends: set[str] | None = None,
    ) -> None:
        baseline = {
            party: (
                self.marker_count(party, NODE_READY_MARKER),
                self.marker_count(party, "standing reservoir ready:"),
                self.reservoir_rebuild_count(party),
            )
            for party in PARTIES
        }
        self.compose("up", "--no-build", "--detach", *PARTIES)
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            ready = True
            for party in PARTIES:
                container = self.compose(
                    "ps", "--all", "--quiet", party, capture=True
                ).stdout.strip()
                if not container:
                    ready = False
                    continue
                state = self.command(
                    ["docker", "inspect", "--format", "{{.State.Status}}", container],
                    check=False,
                    capture=True,
                ).stdout.strip()
                before_node, before_reservoir, _ = baseline[party]
                if (
                    state != "running"
                    or self.marker_count(party, NODE_READY_MARKER) <= before_node
                    or self.marker_count(party, "standing reservoir ready:")
                    < before_reservoir + expected_programs
                ):
                    ready = False
            if ready:
                if expected_rebuild is not None:
                    expected = expected_programs if expected_rebuild else 0
                    agreed_generations: dict[str, str] | None = None
                    for party in PARTIES:
                        observed = self.reservoir_rebuild_count(party) - baseline[party][2]
                        if observed != expected:
                            raise AcceptanceFailure(
                                f"{party} rebuilt {observed} reservoirs; expected {expected}"
                            )
                        ready_lines = [
                            line
                            for line in self.logs(party).splitlines()
                            if "standing reservoir ready:" in line
                        ][baseline[party][1] :]
                        generations = {
                            match.group(1): match.group(2)
                            for line in ready_lines
                            if (
                                match := re.search(
                                    r"program=([0-9a-f]{64}).*generation=([0-9a-f]{64})",
                                    line,
                                )
                            )
                        }
                        if len(generations) != expected_programs:
                            raise AcceptanceFailure(
                                f"{party} did not report {expected_programs} complete reservoir generations"
                            )
                        if agreed_generations is None:
                            agreed_generations = generations
                        elif generations != agreed_generations:
                            raise AcceptanceFailure(
                                f"startup reservoir generations diverged on {party}"
                            )
                self.assert_reservoir_backends(baseline, expected_backends)
                return
            time.sleep(2)
        raise AcceptanceFailure(
            "timed out waiting for five standing nodes and reservoirs"
        )

    def assert_reservoir_backends(
        self,
        baseline: dict[str, tuple[int, int, int]],
        expected_backends: set[str] | None,
    ) -> None:
        """Pin which MPC backends each party actually warmed a reservoir for.

        A standing node takes a program's backend from its artifact manifest,
        not from the submission, so the matrix saying `"backend": "avss"` is a
        claim about the fixture rather than a measurement. Point the AVSS
        catalog entry at a HoneyBadger artifact and every other assertion in
        this campaign still passes while no AVSS reservoir is ever built —
        which would quietly retire the only live coverage AVSS preprocessing
        has, including the `top_up_exact` path the §9.1 V-0 fix changed.

        So read the backend each party reports on its own reservoir-ready
        lines and require the set to be exactly what the caller expects.
        """
        if expected_backends is None:
            return
        for party in PARTIES:
            ready_lines = [
                line
                for line in self.logs(party).splitlines()
                if "standing reservoir ready:" in line
            ][baseline[party][1] :]
            observed = {
                match.group(1)
                for line in ready_lines
                if (match := re.search(r"backend=(\S+)", line))
            }
            if observed != expected_backends:
                raise AcceptanceFailure(
                    f"{party} warmed reservoirs for backends {sorted(observed)}; "
                    f"expected exactly {sorted(expected_backends)}. A catalog that "
                    "no longer holds an artifact for every backend narrows this "
                    "campaign's coverage without failing any other assertion."
                )

    def node_snapshot(self) -> dict[str, tuple[str, str]]:
        snapshot = {}
        for party in PARTIES:
            container = self.compose(
                "ps", "--quiet", party, capture=True
            ).stdout.strip()
            identity = self.command(
                ["docker", "inspect", "--format", "{{.Id}} {{.State.Pid}}", container],
                capture=True,
            ).stdout.strip()
            snapshot[party] = tuple(identity.split())  # type: ignore[assignment]
        return snapshot

    def assert_snapshot(self, expected: dict[str, tuple[str, str]]) -> None:
        if self.node_snapshot() != expected:
            raise AcceptanceFailure("a standing party container or process changed")

    def submit(self, execution: dict[str, Any]) -> str:
        """Ask the coordinator to run `execution`, and take the identity it minted.

        The driver supplies no identity: `--execution-id` does not exist on a
        node and this tool has no way to name one. What comes back is what the
        coordinator minted and has already published to every roster node.
        """
        clients = execution.get("clients", [])
        slots = {int(client["manifest_slot"]) for client in clients}
        if len(slots) != len(clients):
            raise AcceptanceFailure(
                f"execution {execution['name']} names a manifest slot twice"
            )
        slot_table = [
            f"{len(client.get('inputs', []))}:{int(client['outputs'])}"
            for client in sorted(clients, key=lambda item: int(item["manifest_slot"]))
        ]
        arguments = [
            "submit",
            "--coordinator",
            COORDINATOR,
            "--coord-cert",
            COORDINATOR_CERT,
            "--cert",
            OPERATOR_CERT,
            "--key",
            OPERATOR_KEY,
            "--program",
            execution["program_id"],
            "--entry",
            execution.get("entry", "main"),
        ]
        if slot_table:
            arguments.extend(["--client-slots", ",".join(slot_table)])
        # The order of `--client` is the execution-local ordinal the MPC backend
        # numbers clients by, which is deliberately not the program's slot: the
        # matrix lists one execution whose ordinals permute its slots, and that
        # permutation is the only coverage of the two index spaces being
        # distinct.
        for client in clients:
            arguments.extend(
                [
                    "--client",
                    f"{int(client['manifest_slot'])}={CLIENT_CERT_DIR}/{client['certificate']}",
                ]
            )
        result = self.operator(arguments)
        # `docker compose run` narrates the one-off operator container on the
        # same stream this harness captures, so the minted identity is the last
        # line of the output rather than the whole of it. The line itself is
        # still required to be exactly what `stoffel-coord-ctl submit` prints:
        # the execution identity and the registration nonce, nothing else.
        lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
        minted = lines[-1].split() if lines else []
        if len(minted) != 2 or not HEX_ID.fullmatch(minted[0]):
            raise AcceptanceFailure(
                f"the coordinator did not mint an identity for {execution['name']}: {result.stdout!r}"
            )
        execution["execution_id"] = minted[0]
        execution["registration_nonce"] = minted[1]
        return minted[0]

    def abort(self, execution: dict[str, Any]) -> None:
        """Ask the coordinator to stop `execution` on every node running it."""
        self.operator(
            [
                "abort",
                "--coordinator",
                COORDINATOR,
                "--coord-cert",
                COORDINATOR_CERT,
                "--cert",
                OPERATOR_CERT,
                "--key",
                OPERATOR_KEY,
                "--execution",
                execution["execution_id"],
            ]
        )

    def operator(
        self, arguments: list[str], check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return self.compose(
            "--profile",
            "tools",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "operator",
            *arguments,
            capture=True,
            check=check,
        )

    def assert_submission_refused(
        self, arguments: list[str], expected: str, snapshot: dict[str, tuple[str, str]]
    ) -> None:
        """A submission the coordinator refuses must change nothing anywhere.

        This replaces the malformed-command-file cases of the mounted control
        plane. The thing that can now be malformed is a submission, and the
        party that refuses it is the coordinator, before any node hears of it.
        """
        result = self.operator(arguments, check=False)
        combined = f"{result.stdout}{result.stderr}"
        if result.returncode == 0 or expected not in combined:
            raise AcceptanceFailure(
                f"expected a refusal naming {expected!r}, got rc={result.returncode}: {combined}"
            )
        self.assert_snapshot(snapshot)

    def node_events(self, party: str) -> list[dict[str, Any]]:
        """Every execution lifecycle line this party has printed, in order."""
        events = []
        for line in self.logs(party, timestamps=True).splitlines():
            match = NODE_EVENT.search(line)
            if match is None:
                continue
            stamp = LOG_TIMESTAMP.search(line)
            phase = match.group("phase")
            events.append(
                {
                    "execution_id": match.group("execution"),
                    "event": PHASE_NAMES.get(phase, phase),
                    "detail": match.group("detail") or "",
                    "at": log_timestamp_ns(stamp.group(1)) if stamp else 0,
                }
            )
        return events

    def find_event(
        self, party: str, predicate: Callable[[dict[str, Any]], bool]
    ) -> dict[str, Any] | None:
        for event in self.node_events(party):
            if predicate(event):
                return event
        return None

    def wait_event(
        self,
        party: str,
        predicate: Callable[[dict[str, Any]], bool],
        description: str,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + (timeout or self.wait_seconds)
        while time.monotonic() < deadline:
            event = self.find_event(party, predicate)
            if event is not None:
                return event
            time.sleep(0.2)
        raise AcceptanceFailure(f"timed out waiting for {description} on {party}")

    def expect_admitted(
        self, execution: dict[str, Any], timeout: int | None = None
    ) -> None:
        """Every party admitted the execution the coordinator published."""
        identifier = execution["execution_id"]
        pattern = f"admitted execution {identifier}"
        deadline = time.monotonic() + (timeout or self.wait_seconds)
        pending = list(PARTIES)
        while pending and time.monotonic() < deadline:
            for party in list(pending):
                logs = self.logs(party)
                refused = [
                    match.group("error")
                    for match in (NODE_REFUSED.search(line) for line in logs.splitlines())
                    if match is not None and match.group("execution") == identifier
                ]
                if refused:
                    raise AcceptanceFailure(
                        f"{party} refused execution {execution['name']}: {refused[-1]}"
                    )
                if pattern in logs:
                    pending.remove(party)
            if pending:
                time.sleep(0.2)
        if pending:
            raise AcceptanceFailure(
                f"execution {execution['name']} was not admitted on {pending}"
            )
        self.admitted_identities.add(identifier)

    def expect_ready(
        self,
        execution: dict[str, Any],
        timeout: int | None = None,
    ) -> dict[str, dict[str, Any]]:
        self.expect_admitted(execution, timeout)
        identifier = execution["execution_id"]
        ready = {}
        for party in PARTIES:
            preparing = self.wait_event(
                party,
                lambda item: item["execution_id"] == identifier
                and item["event"] in {"preparing", "ready", "failed", "cancelled"},
                f"execution {identifier} preparing",
                timeout,
            )
            if preparing["event"] not in {"preparing", "ready"}:
                raise AcceptanceFailure(
                    f"execution {execution['name']} did not reach Preparing on {party}: {preparing}"
                )
            event = self.wait_event(
                party,
                lambda item: item["execution_id"] == identifier
                and item["event"] in {"ready", "failed", "cancelled"},
                f"execution {identifier} ready",
                timeout,
            )
            if event["event"] != "ready":
                raise AcceptanceFailure(
                    f"execution {execution['name']} did not become Ready on {party}: {event}"
                )
            ready[party] = event
        return ready

    def terminal(
        self,
        execution: str,
        party: str,
        phases: set[str] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        phases = phases or {"Completed", "Failed", "Cancelled"}
        lowered = {phase.lower() for phase in phases}
        event = self.wait_event(
            party,
            lambda item: item["execution_id"] == execution
            and item["event"] in lowered,
            f"terminal execution {execution}",
            timeout,
        )
        if event["event"] not in lowered:
            raise AcceptanceFailure(
                f"execution {execution} reached {event['event']}, expected {sorted(lowered)}: {event}"
            )
        return event

    def start_client(
        self, prefix: str, execution: dict[str, Any], client: dict[str, Any]
    ) -> ClientJob:
        certificate = str(client["certificate"])
        match = re.fullmatch(r"cert([01])\.crt", certificate)
        if match is None:
            raise AcceptanceFailure(
                f"unsupported Compose client certificate {certificate!r}"
            )
        identity_slot = int(match.group(1))
        manifest_slot = int(client["manifest_slot"])
        label = (
            f"{prefix}-{execution['name']}-client{identity_slot}-slot{manifest_slot}"
        )
        container = f"{self.project}-{re.sub('[^a-zA-Z0-9_.-]', '-', label)}"
        log = self.state / "logs" / f"{label}.log"
        args = self.compose_args(
            "--profile",
            "tools",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--name",
            container,
            "--entrypoint",
            "/app/stoffel-run",
            f"client{identity_slot}",
            "--client",
            "--execution-id",
            execution["execution_id"],
            "--program",
            f"/var/lib/stoffel/programs/{execution['program_id']}.stflb",
            "--client-slot",
            str(manifest_slot),
        )
        inputs = client.get("inputs", [])
        if inputs:
            args.extend(["--inputs", ",".join(str(value) for value in inputs)])
        args.extend(
            [
                "--outputs",
                str(client["outputs"]),
                "--servers",
                NODE_RPC_SERVERS,
                "--client-transport-servers",
                NODE_CLIENT_TRANSPORT_SERVERS,
                "--off-chain-coord",
                COORDINATOR,
                # Every coordinator connection pins the coordinator's key.
                "--coord-cert",
                COORDINATOR_CERT,
                "--n-parties",
                "5",
                "--threshold",
                "1",
                "--mpc-backend",
                execution["backend"],
                "--mpc-curve",
                execution["curve"],
                "--cert",
                "/run/secrets/stoffel_identity.crt",
                "--key",
                "/run/secrets/stoffel_identity.key",
            ]
        )
        stream = log.open("w", encoding="utf-8")
        process = subprocess.Popen(
            args,
            cwd=self.root,
            env=self.env,
            text=True,
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        job = ClientJob(
            label,
            container,
            process,
            stream,
            log,
            list(client.get("expected", [])),
            int(client["outputs"]),
        )
        self.client_jobs.append(job)
        return job

    def wait_client(self, job: ClientJob, timeout: int | None = None) -> None:
        deadline = time.monotonic() + (timeout or self.protocol_seconds + 30)
        while job.process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.2)
        if job.process.poll() is None:
            self.command(["docker", "rm", "--force", job.container], check=False)
            job.process.wait(timeout=10)
            job.stream.close()
            raise AcceptanceFailure(f"client {job.label} timed out; see {job.log}")
        job.stream.close()
        output = job.log.read_text(encoding="utf-8")
        if job.process.returncode != 0:
            raise AcceptanceFailure(
                f"client {job.label} failed; see {job.log}\n{output}"
            )
        if job.outputs and f"outputs: {job.expected}" not in output:
            raise AcceptanceFailure(
                f"client {job.label} expected {job.expected}; see {job.log}\n{output}"
            )

    def assert_unauthorized_client(self, execution: dict[str, Any]) -> None:
        snapshot = self.node_snapshot()
        rogue = self.start_client(
            "unauthorized",
            execution,
            {
                "certificate": "cert1.crt",
                "manifest_slot": 0,
                "inputs": [99],
                "outputs": 1,
                "expected": [],
            },
        )
        time.sleep(3)
        if rogue.process.poll() is None:
            self.command(["docker", "rm", "--force", rogue.container], check=False)
            rogue.process.wait(timeout=10)
        rogue.stream.close()
        output = rogue.log.read_text(encoding="utf-8")
        if "Received INST:" in output or "outputs:" in output:
            raise AcceptanceFailure("an unadmitted client entered the execution")
        self.assert_snapshot(snapshot)

    def run_client_listener_probe(self, *args: str) -> str:
        """Run the adversarial probe as `client1`.

        It runs with `--no-deps` and never contacts the coordinator, so nothing
        but a node can decide its fate. Whether a node will hold its connection
        at all depends on whether some execution admits `cert1` at the time —
        see `probe_certificate_admitted`.
        """
        result = self.compose(
            "--profile",
            "tools",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--entrypoint",
            CLIENT_LISTENER_PROBE,
            "client1",
            *args,
            "--cert",
            "/run/secrets/stoffel_identity.crt",
            "--key",
            "/run/secrets/stoffel_identity.key",
            check=False,
            capture=True,
        )
        output = result.stdout or ""
        if result.returncode != 0:
            raise AcceptanceFailure(
                f"the client-listener probe did not reach the listener:\n{output}"
            )
        return output

    @contextlib.contextmanager
    def probe_certificate_admitted(
        self, program_id: str, backend: str = "honeybadger"
    ) -> Iterator[dict[str, Any]]:
        """Give the probe's certificate a coordinator admission on every node.

        A node's client-facing listener holds a connection only for a
        certificate some execution registered there names
        (`ClientIngressGate`), so an adversary the coordinator admitted nowhere
        is refused before it can reach any boundary beyond the handshake — which
        is the point of that rule, and which would make every probe below it
        untestable from outside. So the probe is given an admission of its own:
        a sibling execution of `program_id` whose published client is `cert1`,
        and which no client ever runs, so it sits Ready until this aborts it.

        What the probes inside this block test is therefore strictly harder than
        what they tested before: a client the coordinator *did* admit, reaching
        for an execution it has no part in, or holding more of a party's
        listener than one certificate may.
        """
        sibling = simple_execution("probe-admission", program_id, 2, 6, backend)
        sibling["clients"][0]["certificate"] = "cert1.crt"
        self.submit(sibling)
        self.expect_ready(sibling, self.coordination_seconds + 30)
        try:
            yield sibling
        finally:
            self.abort(sibling)

    def assert_unadmitted_client_certificate_refused(self) -> None:
        """A certificate the coordinator admitted nowhere here holds no connection.

        This is the rule the occupancy caps are bounds *within*: certificates
        are free and this listener carries no allowlist, so anything stated per
        certificate is defeated by churning them. The probe floods one party
        with connections while no execution admits its certificate, and the
        party must report refusing them as unadmitted — not as over capacity,
        which is what it would report if the rule had been reduced back to a cap
        — and stay up.
        """
        snapshot = self.node_snapshot()
        connections = 8
        output = self.run_client_listener_probe(
            "flood",
            "--servers",
            NODE_CLIENT_TRANSPORT_SERVERS.split(",")[0],
            "--connections",
            str(connections),
            "--connect-timeout-ms",
            "20000",
            "--hold-ms",
            "5000",
        )
        handshakes = PROBE_FLOOD_HANDSHAKES.search(output)
        if handshakes is None or int(handshakes.group("completed")) == 0:
            raise AcceptanceFailure(
                f"the probe reached no handshake, so no refusal was tested:\n{output}"
            )
        # Every connection that got through the handshake reached the gate, and
        # every one of those is a refusal the party owes an operator: a refusal
        # a node does not report is a refusal nobody can audit.
        owed = int(handshakes.group("completed"))
        refused = []
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            refused = [
                int(match.group("unadmitted"))
                for match in (
                    CLIENT_INGRESS_UNADMITTED.search(line)
                    for line in self.logs(PARTIES[0]).splitlines()
                )
                if match is not None
            ]
            if sum(refused) >= owed:
                break
            time.sleep(0.5)
        else:
            raise AcceptanceFailure(
                f"{PARTIES[0]} completed {owed} of {connections} handshakes from a certificate "
                f"no execution admits but reported refusing only {sum(refused)} of them"
            )
        self.assert_snapshot(snapshot)

    def assert_unadmitted_client_route_refused(self, execution: dict[str, Any]) -> None:
        """The boundary the two-listener split rests on, tested from outside the node.

        `assert_unauthorized_client` tests the coordinator's refusal to
        *associate* an unadmitted client, which is a different boundary and the
        only one a client with inputs ever reaches: `--client-transport-servers`
        is read only by an output-only client, and association happens first.
        This dials a node's `--client-bind` socket directly and asks for a route
        into an execution whose published admission does not name the probe's
        certificate, so the node's per-execution client roster is the only thing
        that can refuse it.

        Call it inside `probe_certificate_admitted`: the socket itself now holds
        a connection only for a certificate the coordinator admitted somewhere
        on that node, so without an admission of its own the probe is refused at
        the handshake and never reaches this boundary.
        """
        snapshot = self.node_snapshot()
        identifier = execution["execution_id"]
        output = self.run_client_listener_probe(
            "route",
            "--servers",
            NODE_CLIENT_TRANSPORT_SERVERS,
            "--execution-id",
            identifier,
        )
        announced = output.count("probe: route hello sent to ")
        if announced != len(PARTIES):
            raise AcceptanceFailure(
                f"the probe announced {announced} routes, expected {len(PARTIES)}:\n{output}"
            )
        for party in PARTIES:
            refusals = [
                match.group("execution")
                for match in (
                    CLIENT_ROUTE_REFUSED.search(line)
                    for line in self.logs(party).splitlines()
                )
                if match is not None and match.group("refused") == match.group("execution")
            ]
            if identifier not in refusals:
                raise AcceptanceFailure(
                    f"{party} did not refuse an unadmitted client route for {identifier}; "
                    f"refusals seen: {refusals}"
                )
        self.assert_snapshot(snapshot)

    def assert_client_connection_flood_refused(self, connections: int = 272) -> None:
        """One certificate cannot occupy the client-facing listener without bound.

        Not even a certificate the coordinator admitted may hold the whole of a
        party's listener. The probe opens more than
        `ClientIngressLimits::standing_node`'s per-certificate allowance (256)
        against one party and holds them all at once, and that party must report
        refusing the surplus. It is the per-certificate cap rather than the total
        cap that is probed here, because reaching the total cap would mean over a
        thousand concurrent handshakes from a transient container; the total cap
        is pinned in-process by
        `roster.rs::the_client_facing_listener_refuses_connections_past_its_cap`,
        and what keeps a flood of certificates the coordinator never admitted
        from reaching either cap by
        `roster.rs::a_flood_of_unnamed_certificates_cannot_lock_out_an_admitted_client_over_quic`
        and, from outside the node, by
        `assert_unadmitted_client_certificate_refused`.

        Call it inside `probe_certificate_admitted`: an unadmitted certificate is
        refused by the listener's first question and would never reach the cap
        this asserts on.

        That the node is still *serving* afterwards is asserted by the
        executions `run_adversarial` runs after this, not just by the snapshot.
        """
        snapshot = self.node_snapshot()
        output = self.run_client_listener_probe(
            "flood",
            "--servers",
            NODE_CLIENT_TRANSPORT_SERVERS.split(",")[0],
            "--connections",
            str(connections),
            # Every handshake is sequential, and the node prunes its occupancy
            # table once a cap is reached, so give the last of them room over a
            # container bridge rather than the probe's loopback-sized default.
            "--connect-timeout-ms",
            "20000",
            "--hold-ms",
            "5000",
        )
        if "probe: flood held " not in output:
            raise AcceptanceFailure(
                f"the flood probe held no connections:\n{output}"
            )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            over = [
                int(match.group("over_capacity"))
                for match in (
                    CLIENT_INGRESS_REFUSED.search(line)
                    for line in self.logs(PARTIES[0]).splitlines()
                )
                if match is not None
            ]
            if any(count > 0 for count in over):
                break
            time.sleep(0.5)
        else:
            raise AcceptanceFailure(
                f"{PARTIES[0]} accepted {connections} connections from one certificate "
                "without reporting a capacity refusal"
            )
        self.assert_snapshot(snapshot)

    def assert_completed(
        self,
        execution: dict[str, Any],
        parties: Iterable[str] = PARTIES,
        timeout: int | None = None,
        yield_kind: str = "cooperative",
    ) -> dict[str, dict[str, Any]]:
        parties = tuple(parties)
        events = {}
        for party in parties:
            event = self.terminal(
                execution["execution_id"],
                party,
                {"Completed", "Failed", "Cancelled"},
                timeout,
            )
            if event["event"] != "completed":
                raise AcceptanceFailure(
                    f"execution {execution['name']} failed on {party}: {event}"
                )
            metrics = yield_counts(event)
            event["metrics"] = metrics
            if yield_kind == "instruction":
                progressed = metrics["instruction_budget_yields"] > 0
            elif yield_kind == "online":
                progressed = metrics["online_effect_yields"] > 0
            else:
                progressed = (
                    metrics["instruction_budget_yields"]
                    + metrics["online_effect_yields"]
                    > 0
                )
            if not progressed:
                raise AcceptanceFailure(
                    f"execution {execution['name']} did not cooperatively yield on {party}"
                )
            events[party] = event
        digests = set()
        marker = (
            f"[execution {execution['execution_id']}] reservoir allocation ready:"
        )
        for party in parties:
            lines = [line for line in self.logs(party).splitlines() if marker in line]
            if len(lines) != 1:
                raise AcceptanceFailure(
                    f"expected one destructive allocation for {execution['name']} on {party}, found {len(lines)}"
                )
            match = re.search(r"\bdigest=([0-9a-f]{64})\b", lines[0])
            if match is None:
                raise AcceptanceFailure(
                    f"allocation digest missing for {execution['name']} on {party}"
                )
            digests.add(match.group(1))
        if len(digests) != 1:
            raise AcceptanceFailure(
                f"parties allocated different material for {execution['name']}: {digests}"
            )
        digest = digests.pop()
        prior = self.allocation_digests.get(execution["execution_id"])
        if prior is not None and prior != digest:
            raise AcceptanceFailure(
                f"execution {execution['name']} changed allocation digest"
            )
        if any(
            other_id != execution["execution_id"] and other_digest == digest
            for other_id, other_digest in self.allocation_digests.items()
        ):
            raise AcceptanceFailure(
                f"execution {execution['name']} reused another execution's allocation digest"
            )
        self.allocation_digests[execution["execution_id"]] = digest
        self.assert_inventory_decreases_between_refills(parties)
        return events

    def assert_inventory_decreases_between_refills(
        self, parties: Iterable[str]
    ) -> None:
        reset = re.compile(
            r"(?:standing reservoir ready:|RESERVOIR_REFILL_COMPLETED) program=([0-9a-f]{64})"
        )
        allocation = re.compile(
            r"reservoir allocation ready: program=([0-9a-f]{64}).*"
            r"remaining=PoolAvailability \{ beaver: (\d+), random: (\d+), "
            r"prand_bit: (\d+), prand_int: (\d+) \}"
        )
        for party in parties:
            previous: dict[str, tuple[int, ...]] = {}
            for line in self.logs(party).splitlines():
                if match := reset.search(line):
                    previous.pop(match.group(1), None)
                if match := allocation.search(line):
                    program = match.group(1)
                    remaining = tuple(int(value) for value in match.groups()[1:])
                    before = previous.get(program)
                    if before is not None and any(
                        current > prior
                        for current, prior in zip(remaining, before, strict=True)
                    ):
                        raise AcceptanceFailure(
                            f"{party} inventory increased without a refill for program {program}: {before} -> {remaining}"
                        )
                    previous[program] = remaining

    def run_wave(
        self,
        prefix: str,
        executions: list[dict[str, Any]],
    ) -> dict[str, dict[str, dict[str, Any]]]:
        # Submission is serial and the coordinator publishes each execution as
        # it is minted, so the wave is concurrent from the nodes' side even
        # though the operator asks for one execution at a time.
        for execution in executions:
            self.submit(execution)
        ready = {
            execution["name"]: self.expect_ready(execution) for execution in executions
        }

        clients = [
            self.start_client(prefix, execution, client)
            for execution in executions
            for client in execution.get("clients", [])
        ]
        for client in clients:
            self.wait_client(client)

        completed = {
            execution["name"]: self.assert_completed(execution)
            for execution in executions
        }
        for execution in executions:
            name = execution["name"]
            for party in PARTIES:
                completed[name][party]["_ready_at"] = ready[name][party]["at"]
        return completed

    def assert_overlap(
        self,
        executions: list[dict[str, Any]],
        completed: dict[str, dict[str, dict[str, Any]]],
        parties: Iterable[str] = PARTIES,
    ) -> None:
        for party in parties:
            intervals = [
                (
                    int(completed[item["name"]][party]["_ready_at"]),
                    int(completed[item["name"]][party]["at"]),
                )
                for item in executions
            ]
            if max(start for start, _ in intervals) >= min(
                finish for _, finish in intervals
            ):
                raise AcceptanceFailure(
                    f"execution intervals did not overlap on {party}: {intervals}"
                )

    def stop_nodes(self) -> None:
        self.compose("stop", *PARTIES)

    def kill_nodes(self) -> None:
        self.compose("kill", "--signal", "SIGKILL", *PARTIES)

    def node_ready_baseline(self) -> dict[str, int]:
        """How many startup lines each party has printed up to now.

        `kill_nodes` + `start_nodes` restarts the same containers, which keep
        every line the dead process wrote, and `logs` reads a container's whole
        history. Anything that means to observe the restarted process therefore
        has to take this baseline before the kill and read only past it;
        `start_nodes` already does the same thing for its readiness markers.
        """
        return {party: self.marker_count(party, NODE_READY_MARKER) for party in PARTIES}

    def assert_admission_index_survived_restart(self, baseline: dict[str, int]) -> None:
        """The restarted process reopened the admission index its predecessor wrote.

        A node prints the size of its durable admission index once, on startup,
        before it has read anything off the coordinator's stream, so the number
        in the line past `baseline` is the retained history and nothing the new
        process has admitted since. The campaign opened with `down --volumes`
        and this is the deployment's second startup, so the party's first line
        reported an empty index: the count has to have moved, and it has to
        cover every identity this campaign watched all five parties admit. An
        index lost with the process — or one never reopened — reports zero and
        fails both halves.
        """
        owed = len(self.admitted_identities)
        if owed == 0:
            raise AcceptanceFailure(
                "no admitted identity was recorded before the restart, so this arm "
                "would pass against a node that reopened nothing"
            )
        for party in PARTIES:
            if baseline[party] < 1:
                raise AcceptanceFailure(
                    f"{party} had printed no startup line before the SIGKILL, so there "
                    "is nothing to compare the restarted process against"
                )
            lines = [
                line
                for line in self.logs(party).splitlines()
                if NODE_READY_MARKER in line
            ]
            after = lines[baseline[party] :]
            if not after:
                raise AcceptanceFailure(
                    f"{party} printed no startup line after the SIGKILL restart"
                )
            sizes: list[int] = []
            for line in (lines[baseline[party] - 1], after[-1]):
                match = NODE_READY.search(line)
                if match is None:
                    raise AcceptanceFailure(
                        f"{party} reported no admission-index size on startup: {line!r}"
                    )
                sizes.append(int(match.group("identities")))
            before, held = sizes
            if held < owed:
                raise AcceptanceFailure(
                    f"{party} reopened an admission index holding {held} identities "
                    f"after the SIGKILL; the {owed} identities this deployment has "
                    "admitted must all still be in it"
                )
            if before >= held:
                raise AcceptanceFailure(
                    f"{party} reported {before} admitted identities before the "
                    f"SIGKILL and {held} after it; the restarted process is not "
                    "reading a store that grew while it ran"
                )

    def remove_party2_preprocessing(self) -> None:
        container = self.compose(
            "ps", "--all", "--quiet", "party2", capture=True
        ).stdout.strip()
        volume = self.command(
            [
                "docker",
                "inspect",
                "--format",
                '{{range .Mounts}}{{if eq .Destination "/var/lib/stoffel/preproc"}}{{.Name}}{{end}}{{end}}',
                container,
            ],
            capture=True,
        ).stdout.strip()
        if not volume:
            raise AcceptanceFailure("could not resolve party2 preprocessing volume")
        self.compose("rm", "--force", "--stop", "party2")
        self.command(["docker", "volume", "rm", volume])

    def pause(self, *parties: str) -> None:
        for party in parties:
            container = self.compose(
                "ps", "--quiet", party, capture=True
            ).stdout.strip()
            self.command(["docker", "pause", container])
            self.paused.add(container)

    def resume_all(self) -> None:
        for container in list(self.paused):
            self.command(["docker", "unpause", container], check=False)
            self.paused.discard(container)

    def discover_network(self) -> None:
        container = self.compose("ps", "--quiet", "party0", capture=True).stdout.strip()
        output = self.command(
            [
                "docker",
                "inspect",
                "--format",
                "{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}",
                container,
            ],
            capture=True,
        ).stdout.splitlines()
        if not output:
            raise AcceptanceFailure("could not discover the standing network")
        self.network = output[0]

    # Cut a party off from the other parties and from nothing else. The peer
    # addresses are the ones the node shaper already knows (`NET_PEER_IPS`),
    # and the coordinator is not among them, so a severed party keeps the link
    # it is told what to run over while losing the mesh it would run it on.
    # This is the same two-band `prio` + `netem` shape that
    # `docker/configure-peer-netem.sh` installs, so severing overwrites
    # whatever shaping the node started with: a stack run with `NET_RTT_MS`,
    # `PARTYn_EXTRA_RTT_MS`, `NET_LOSS` or `NET_BANDWIDTH` set has a root qdisc
    # here, and restoring has to put that shape back rather than delete it.
    SEVER_PEER_LINKS = r"""
interface=${NET_INTERFACE:-eth0}
peers="$(printf '%s' "${NET_PEER_IPS:?NET_PEER_IPS must list the party addresses}" | tr ',' ' ')"
tc qdisc del dev "$interface" root 2>/dev/null || true
tc qdisc replace dev "$interface" root handle 1: prio bands 2 \
  priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
tc qdisc replace dev "$interface" parent 1:1 handle 10: netem loss 100%
for peer in $peers; do
  tc filter add dev "$interface" protocol ip parent 1: prio 1 u32 \
    match ip dst "${peer}/32" flowid 1:1
done
"""
    # Drop the severing qdisc, filters and all, then hand the interface back to
    # the node's own shaper. It reads the same `NET_*` environment the node was
    # started with, which `docker compose exec` carries into this shell, so the
    # party resumes under exactly the shape the campaign configured — and under
    # no shape at all when the campaign configured none, because the shaper
    # exits without touching `tc` in that case.
    RESTORE_PEER_LINKS = r"""
interface=${NET_INTERFACE:-eth0}
tc qdisc del dev "$interface" root 2>/dev/null || true
/app/configure-peer-netem.sh
"""

    def peer_links(self, script: str, *parties: str) -> None:
        for party in parties:
            self.compose(
                "exec",
                "-T",
                "--user",
                "0",
                party,
                "/bin/sh",
                "-ec",
                script,
                capture=True,
            )

    def sever_peer_links(self, *parties: str) -> None:
        self.peer_links(self.SEVER_PEER_LINKS, *parties)

    def restore_peer_links(self, *parties: str) -> None:
        self.peer_links(self.RESTORE_PEER_LINKS, *parties)

    def wait_log(self, path: Path, marker: str, timeout: int | None = None) -> None:
        deadline = time.monotonic() + (timeout or self.wait_seconds)
        while time.monotonic() < deadline:
            if path.is_file() and marker in path.read_text(encoding="utf-8"):
                return
            time.sleep(0.1)
        raise AcceptanceFailure(f"timed out waiting for {marker!r} in {path}")

    def malformed_datagrams(self) -> None:
        # Both sockets a node binds: the roster-pinned mesh and the
        # client-facing listener, which is reachable by anyone and therefore
        # needs this probe at least as much as the mesh does.
        endpoints = " ".join(
            f"172.33.0.{party + 10}:{base + party}"
            for base in (9000, 9100)
            for party in range(5)
        )
        script = (
            f"for endpoint in {endpoints}; do\n"
            "  host=${endpoint%:*}; port=${endpoint##*:}\n"
            "  printf 'not-a-quic-frame' | nc -u -w 1 \"$host\" \"$port\" || true\n"
            "done\n"
        )
        self.compose(
            "--profile",
            "tools",
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--entrypoint",
            "/bin/sh",
            "client1",
            "-ec",
            script,
        )

    def roster_guards(self) -> None:
        common = [
            "--standing-node",
            "--party-id",
            "0",
            "--n-parties",
            "5",
            "--threshold",
            "1",
            "--pool-id",
            execution_id(240),
            "--program-dir",
            "/tmp/programs",
            "--admitted-store",
            "/tmp/admitted",
            "--client-cert-dir",
            "/app/ids/clients",
            "--off-chain-coord",
            COORDINATOR,
            "--bind",
            "127.0.0.1:19000",
            "--client-bind",
            "127.0.0.1:19002",
            "--rpc-bind",
            "127.0.0.1:19001",
        ]
        # The coordinator is the roster authority, so a node that does not pin
        # its certificate must refuse to start at all. This runs with --no-deps,
        # so every case below is decided before any coordinator is dialed.
        for service, roster, pin, expected_error in (
            (
                "party1",
                "/app/ids/nodes",
                "/app/ids/server_cert.crt",
                "does not match",
            ),
            (
                "party0",
                "/app/ids/missing-party-roster",
                "/app/ids/server_cert.crt",
                "read standing party certificate",
            ),
            (
                "party0",
                "/app/ids/nodes",
                None,
                "--off-chain-coord requires --coord-cert",
            ),
        ):
            result = self.compose(
                "--profile",
                "tools",
                "run",
                "--rm",
                "--no-deps",
                "-T",
                "--entrypoint",
                "/app/stoffel-run",
                service,
                *common,
                "--party-cert-dir",
                roster,
                *(("--coord-cert", pin) if pin else ()),
                "--cert",
                "/run/secrets/stoffel_identity.crt",
                "--key",
                "/run/secrets/stoffel_identity.key",
                check=False,
                capture=True,
            )
            if result.returncode == 0:
                raise AcceptanceFailure(
                    f"{service} accepted an invalid party certificate roster"
                )
            if expected_error not in (result.stdout or ""):
                raise AcceptanceFailure(
                    f"{service} failed before enforcing its party roster:\n{result.stdout}"
                )

    def cleanup(self, success: bool) -> None:
        self.resume_all()
        if shutil.which("docker") is not None:
            for job in self.client_jobs:
                if job.process.poll() is None:
                    self.command(
                        ["docker", "rm", "--force", job.container], check=False
                    )
                    try:
                        job.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        job.process.kill()
                        job.process.wait()
                if not job.stream.closed:
                    job.stream.close()
        if not success:
            try:
                (self.state / "logs").mkdir(parents=True, exist_ok=True)
                (self.state / "logs" / "failure-party.log").write_text(
                    self.logs(), encoding="utf-8"
                )
            except Exception:
                pass
        if shutil.which("docker") is not None:
            self.compose(
                "--profile",
                "tools",
                "down",
                "--remove-orphans",
                "--volumes",
                check=False,
            )
        if self.keep_state or not success:
            print(
                f"Standing acceptance state retained at {self.state}", file=sys.stderr
            )
        else:
            shutil.rmtree(self.state, ignore_errors=True)


def load_matrix(harness: Harness) -> list[dict[str, Any]]:
    matrix = json.loads(
        (harness.root / "docker/standing-concurrency/matrix.json").read_text(
            encoding="utf-8"
        )
    )["executions"]
    artifact = {
        ("single_client_io", "honeybadger"): "single-hb",
        ("multi_client_io", "honeybadger"): "multi-hb",
        ("output_only_client_io", "honeybadger"): "output-hb",
        ("multi_client_io", "avss"): "multi-avss",
    }
    for item in matrix:
        if "execution_id" in item:
            raise AcceptanceFailure(
                f"the matrix must not name an execution identity; the coordinator mints it: {item}"
            )
        item["program_id"] = harness.programs[
            artifact[(item["fixture"], item["backend"])]
        ]
    singles = [
        item
        for item in matrix
        if item["fixture"] == "single_client_io" and item["backend"] == "honeybadger"
    ]
    if (
        len(matrix) != 6
        or len({item["name"] for item in matrix}) != 6
        or len(singles) != 3
        or {item["backend"] for item in matrix} != {"honeybadger", "avss"}
        or not any(len(item["clients"]) > 1 for item in matrix)
        or not any(
            any(client["outputs"] == 0 for client in item["clients"])
            and any(not client["inputs"] for client in item["clients"])
            for item in matrix
        )
        or singles[0]["clients"][0]["inputs"] != singles[1]["clients"][0]["inputs"]
        or singles[2]["clients"][0]["inputs"] == singles[0]["clients"][0]["inputs"]
    ):
        raise AcceptanceFailure(
            "matrix does not cover same-program same/different inputs"
        )
    return matrix


def simple_execution(
    name: str,
    program: str,
    value: int,
    expected: int,
    backend: str = "honeybadger",
) -> dict[str, Any]:
    return {
        "name": name,
        "program_id": program,
        "backend": backend,
        "curve": "bls12-381",
        "clients": [
            {
                "certificate": "cert0.crt",
                "manifest_slot": 0,
                "inputs": [value],
                "outputs": 1,
                "expected": [expected],
            }
        ],
    }


def two_client_execution(
    name: str,
    program: str,
    backend: str,
    first: tuple[list[int], list[int]],
    second: tuple[list[int], list[int]],
) -> dict[str, Any]:
    """One execution of a `multi_client_io` fixture, the shape its manifest wants.

    `simple_execution` builds the single-client shape, which the AVSS fixture's
    manifest refuses: `multi-client-io-avss.stflb` has two slots of two inputs
    and two outputs each. Each tuple is (inputs, expected outputs) for one slot.
    """
    return {
        "name": name,
        "program_id": program,
        "backend": backend,
        "curve": "bls12-381",
        "clients": [
            {
                "certificate": certificate,
                "manifest_slot": slot,
                "inputs": inputs,
                "outputs": len(expected),
                "expected": expected,
            }
            for slot, (certificate, (inputs, expected)) in enumerate(
                (("cert0.crt", first), ("cert1.crt", second))
            )
        ],
    }


def run_concurrency(harness: Harness) -> None:
    harness.initialize(
        {
            "single-hb": "/app/standing-fixtures/single-client-io-honeybadger.stflb",
            "multi-hb": "/app/standing-fixtures/multi-client-io-honeybadger.stflb",
            "output-hb": "/app/standing-fixtures/output-only-client-io-honeybadger.stflb",
            "multi-avss": "/app/standing-fixtures/multi-client-io-avss.stflb",
            "cpu-hb": "/app/standing-fixtures/cpu-fairness-honeybadger.stflb",
        }
    )
    matrix = load_matrix(harness)

    print("== Concurrent HoneyBadger/AVSS matrix ==", flush=True)
    harness.start_nodes(
        expected_programs=5, expected_backends=STANDING_BACKENDS
    )
    snapshot = harness.node_snapshot()
    completed = harness.run_wave("fresh", matrix)
    harness.assert_overlap(matrix, completed)

    cpu = [
        {
            "name": "cpu-long",
            "program_id": harness.programs["cpu-hb"],
            "entry": "cpu_long",
            "backend": "honeybadger",
            "clients": [],
        },
        {
            "name": "cpu-short",
            "program_id": harness.programs["cpu-hb"],
            "entry": "cpu_short",
            "backend": "honeybadger",
            "clients": [],
        },
    ]
    cpu_completed = harness.run_wave("fresh", cpu)
    harness.assert_overlap(cpu, cpu_completed)
    for item in cpu:
        for party, event in cpu_completed[item["name"]].items():
            if event["metrics"]["instruction_budget_yields"] < 1:
                raise AcceptanceFailure(
                    f"{item['name']} did not yield its instruction budget on {party}"
                )
    # The short execution overtakes the long one: it starts while the long one
    # is already running and finishes before it. Starting second is what makes
    # the finishing order evidence of instruction-budget yielding rather than of
    # a head start, so both halves are asserted — a pass where the short one
    # began after the long one had already ended would prove nothing.
    for party in PARTIES:
        long_started = int(cpu_completed["cpu-long"][party]["_ready_at"])
        short_started = int(cpu_completed["cpu-short"][party]["_ready_at"])
        short = int(cpu_completed["cpu-short"][party]["at"])
        long = int(cpu_completed["cpu-long"][party]["at"])
        if short_started < long_started:
            raise AcceptanceFailure(
                f"CPU-short started before CPU-long on {party}, so finishing "
                "first would not show the scheduler yielding"
            )
        if short_started >= long:
            raise AcceptanceFailure(
                f"CPU-short started after CPU-long had finished on {party}: the "
                "two never competed for the process"
            )
        if short >= long:
            raise AcceptanceFailure(
                f"CPU-short did not finish before CPU-long on {party}"
            )
    harness.assert_snapshot(snapshot)

    print("== Retained preprocessing volumes and durable admission index ==", flush=True)
    # The identities admitted before the SIGKILL are still refused after it:
    # `--admitted-store` is retained with the preprocessing volume, so a
    # republished identity can never re-run against material its peers already
    # consumed. A docker driver can no longer construct the replay that used to
    # probe this — an operator cannot name an identity and the coordinator mints
    # a fresh one for every submission — so the probe is the other end of the
    # same mechanism: each restarted process reports the size of the index it
    # reopened, before it has read anything off the coordinator's stream, and
    # that number has to account for everything this deployment admitted while
    # the dead process was running. The baseline is taken before the kill
    # because the containers keep their predecessor's log. The refusal itself and
    # the number this reads are pinned by
    # `storage::retired_executions::tests::a_claim_survives_the_process_that_made_it`
    # and `::a_reopened_index_reports_every_identity_it_retained`.
    ready_baseline = harness.node_ready_baseline()
    # Taken before the kill, like ready_baseline and for the same reason: the
    # restarted process writes into its predecessor's container log.
    avss_agreement_baseline = harness.agreement_action_baseline("AVSS")
    harness.kill_nodes()
    harness.start_nodes(
        expected_programs=5,
        expected_rebuild=False,
        expected_backends=STANDING_BACKENDS,
    )
    snapshot = harness.node_snapshot()
    harness.assert_admission_index_survived_restart(ready_baseline)
    # The AVSS reservoir comes back PARTIALLY full, so this restart is the one
    # place any suite reaches AVSS `top_up_exact` over a non-empty pool. The
    # fresh wave's `avss-multi-io` drew from the scope and the draw physically
    # removes, so the re-warm finds one allocation's worth missing against
    # targets of `per_execution x (burst_capacity + 1)` and agrees `TopUp`.
    # Exactly one, because the catalog holds exactly one AVSS program. The
    # Rebuild half is pinned by `expected_rebuild=False` above; this pins the
    # distinction that leaves cannot see — `TopUp` rather than `Reuse`.
    harness.assert_agreement_actions(
        "AVSS", avss_agreement_baseline, {"TopUp": 1}
    )
    print(
        "   every party agreed AVSS action=TopUp across the restart",
        flush=True,
    )
    avss_refill_marker = (
        f"RESERVOIR_REFILL_COMPLETED program={harness.programs['multi-avss']}"
    )
    # Before the first AVSS allocation below, because those allocations are
    # what drive the refill this baseline is measured against.
    avss_refill_baseline = {
        party: harness.marker_count(party, avss_refill_marker) for party in PARTIES
    }
    # And then DRAW from what the top-up produced. Before this the
    # retained, post-refill and asymmetric waves were all HoneyBadger, so
    # nothing ever allocated out of a topped-up AVSS reservoir and three live
    # checks were vacuous for AVSS: the destructive-allocation digest had no
    # second AVSS digest to differ from, and
    # `assert_inventory_decreases_between_refills` needs two allocations
    # between resets to compare anything at all — the restart's
    # `standing reservoir ready:` line resets it, and the fresh wave's single
    # AVSS allocation sat before that. The executions below make both real.
    # Two are spelled out here; the seven that follow cycle their inputs.
    topped_up_avss = [
        # Deliberately the same inputs as the fresh wave's `avss-multi-io`, so
        # the cleartext is identical and the allocation digests still have to
        # differ. That is the single-use property under the hardest condition
        # the campaign can arrange.
        two_client_execution(
            "retained-avss-a",
            harness.programs["multi-avss"],
            "avss",
            ([2, 3], [2 * 4 + 3 * 5, 2 + 3]),
            ([4, 5], [2 + 3 + 4 + 5, 4 + 5]),
        ),
        # Different inputs, so a topped-up reservoir is also shown computing a
        # different correct answer rather than only repeating one.
        two_client_execution(
            "retained-avss-b",
            harness.programs["multi-avss"],
            "avss",
            ([6, 1], [6 * 3 + 1 * 8, 6 + 1]),
            ([3, 8], [6 + 1 + 3 + 8, 3 + 8]),
        ),
    ]
    # Nine allocations is what crosses `availability_reached_refill_threshold`
    # (stoffel-run.rs), because the restart warmed the scope to
    # `per_execution x (burst_capacity + 1)` and the gate fires when what is
    # left has fallen to one execution's worth. Reaching it drives
    # `spawn_synchronized_reservoir_refill` — a top-up running CONCURRENTLY
    # with a live deployment, holding the program lane — which the HoneyBadger
    # side of this campaign has always exercised and the AVSS side never has.
    # The two draws above are its first two allocations, so the remaining seven
    # are the whole additional cost: measured, the arm adds 68 s to a 481 s
    # campaign, which is why it runs by default rather than behind a flag.
    #
    # Same two input sets, cycled: identical cleartext across nine executions,
    # so the allocation digests still have to differ nine ways. Submitted three
    # at a time rather than nine, because what is new here is AVSS meeting a
    # concurrent refill, not AVSS meeting eighteen simultaneous client
    # containers - and the HoneyBadger block above already covers nine-way
    # concurrency against a refill.
    template = list(topped_up_avss)
    for index in range(len(template), 9):
        drained = dict(template[index % len(template)])
        drained["name"] = f"retained-avss-{chr(ord('a') + index)}"
        topped_up_avss.append(drained)
    for start in range(0, len(topped_up_avss), 3):
        batch = topped_up_avss[start : start + 3]
        harness.assert_overlap(batch, harness.run_wave("retained-avss", batch))
    print(
        f"   {len(topped_up_avss)} AVSS execution(s) drew from the topped-up reservoir",
        flush=True,
    )

    avss_refill_deadline = time.monotonic() + harness.wait_seconds
    while time.monotonic() < avss_refill_deadline:
        if all(
            harness.marker_count(party, avss_refill_marker)
            > avss_refill_baseline[party]
            for party in PARTIES
        ):
            break
        time.sleep(1)
    else:
        raise AcceptanceFailure(
            "the AVSS reservoir did not refill elastically on every party"
        )
    # Two more, out of what the concurrent refill produced rather than out of
    # what the restart's top-up left: the refill is only worth asserting if the
    # reservoir it refilled goes on to serve.
    post_refill_avss = []
    for index, execution in enumerate(topped_up_avss[:2]):
        drawn = dict(execution)
        drawn["name"] = f"post-refill-avss-{chr(ord('a') + index)}"
        post_refill_avss.append(drawn)
    harness.assert_overlap(
        post_refill_avss, harness.run_wave("retained-avss", post_refill_avss)
    )
    print(
        "   the AVSS reservoir refilled elastically and served "
        f"{len(post_refill_avss)} more execution(s)",
        flush=True,
    )

    refill_marker = (
        f"RESERVOIR_REFILL_COMPLETED program={harness.programs['single-hb']}"
    )
    refill_baseline = {
        party: harness.marker_count(party, refill_marker) for party in PARTIES
    }
    retained = [
        simple_execution("retained-a", harness.programs["single-hb"], 8, 24),
        simple_execution("retained-b", harness.programs["single-hb"], 5, 15),
        simple_execution("retained-c", harness.programs["single-hb"], 2, 6),
        simple_execution("retained-d", harness.programs["single-hb"], 9, 27),
        simple_execution("retained-e", harness.programs["single-hb"], 12, 36),
        simple_execution("retained-f", harness.programs["single-hb"], 4, 12),
        simple_execution("retained-g", harness.programs["single-hb"], 7, 21),
        simple_execution("retained-h", harness.programs["single-hb"], 11, 33),
        simple_execution("retained-i", harness.programs["single-hb"], 13, 39),
    ]
    retained_completed = harness.run_wave("retained", retained)
    harness.assert_overlap(retained, retained_completed)

    refill_deadline = time.monotonic() + harness.wait_seconds
    while time.monotonic() < refill_deadline:
        if all(
            harness.marker_count(party, refill_marker) > refill_baseline[party]
            for party in PARTIES
        ):
            break
        time.sleep(1)
    else:
        raise AcceptanceFailure(
            "single-program reservoir did not refill on every party"
        )

    post_refill = [
        simple_execution("post-refill-a", harness.programs["single-hb"], 3, 9),
        simple_execution("post-refill-b", harness.programs["single-hb"], 10, 30),
    ]
    post_refill_completed = harness.run_wave("retained", post_refill)
    harness.assert_overlap(post_refill, post_refill_completed)
    harness.assert_snapshot(snapshot)

    print("== Asymmetric party2 preprocessing loss and common recovery ==", flush=True)
    harness.stop_nodes()
    harness.remove_party2_preprocessing()
    harness.start_nodes(
        expected_programs=5,
        expected_rebuild=True,
        expected_backends=STANDING_BACKENDS,
    )
    snapshot = harness.node_snapshot()
    recovered = [
        simple_execution("asymmetric-recovery", harness.programs["single-hb"], 6, 18)
    ]
    harness.run_wave("asymmetric", recovered)
    harness.assert_snapshot(snapshot)
    print(
        "Standing concurrency passed: same/different inputs, different programs, "
        "HoneyBadger+AVSS, single/multiple/split client I/O, cooperative CPU fairness, "
        "SIGKILL restart recovery, elastic refill, and asymmetric-store recovery.",
        flush=True,
    )


def prepare_and_run(
    harness: Harness,
    prefix: str,
    execution: dict[str, Any],
    *,
    delayed_party: bool = False,
    unauthorized_probe: bool = False,
) -> None:
    if delayed_party:
        harness.pause("party4")
    harness.submit(execution)
    if delayed_party:
        time.sleep(int(os.environ.get("FAULT_DELAY_SECS", "3")))
        harness.resume_all()
    harness.expect_ready(execution, harness.coordination_seconds + 30)
    if unauthorized_probe:
        # Two different boundaries, both of which have to hold: the
        # coordinator refusing to associate an unadmitted client, and the node
        # refusing an unadmitted route on the listener that authorizes no
        # certificate. The second needs the probe to get onto the socket at all,
        # which on a standing node means holding an admission of its own.
        harness.assert_unauthorized_client(execution)
        with harness.probe_certificate_admitted(
            execution["program_id"], execution.get("backend", "honeybadger")
        ):
            harness.assert_unadmitted_client_route_refused(execution)
    client = harness.start_client(prefix, execution, execution["clients"][0])
    harness.wait_client(client)
    harness.assert_completed(execution, timeout=harness.protocol_seconds + 30)


def run_stalled_sibling(harness: Harness) -> None:
    stalled = simple_execution("absent-client", harness.programs["single-hb"], 1, 3)
    sibling = simple_execution("runnable-sibling", harness.programs["single-hb"], 5, 15)
    for execution in (stalled, sibling):
        harness.submit(execution)
        harness.expect_ready(execution, harness.coordination_seconds + 30)

    sibling_client = harness.start_client("fault", sibling, sibling["clients"][0])
    harness.wait_client(sibling_client)
    sibling_events = harness.assert_completed(sibling)

    for party in PARTIES:
        if harness.find_event(
            party,
            lambda event, identifier=stalled["execution_id"]: event["execution_id"]
            == identifier
            and event["event"] in {"completed", "failed", "cancelled"},
        ):
            raise AcceptanceFailure(
                f"absent-client execution became terminal before sibling progress on {party}"
            )

    # The operator asks the coordinator to abort it, and the coordinator
    # publishes the cancellation to every node running it.
    harness.abort(stalled)
    for party in PARTIES:
        harness.wait_event(
            party,
            lambda event, identifier=stalled["execution_id"]: event["execution_id"]
            == identifier
            and event["event"] == "cancel_accepted",
            f"cancellation of {stalled['execution_id']}",
            30,
        )
        cancelled = harness.terminal(stalled["execution_id"], party, {"Cancelled"}, 30)
        sibling_finished = int(sibling_events[party]["at"])
        stalled_finished = int(cancelled["at"])
        if sibling_finished > stalled_finished:
            raise AcceptanceFailure(
                f"stalled execution resolved before sibling completion on {party}"
            )


def run_adversarial(harness: Harness) -> None:
    harness.initialize(
        {
            "single-hb": "/app/standing-fixtures/single-client-io-honeybadger.stflb",
            "slow-hb": "/app/standing-fixtures/slow-client-io-honeybadger.stflb",
            "single-avss": "/app/standing-fixtures/single-client-io-avss.stflb",
        }
    )
    harness.roster_guards()
    harness.start_nodes(
        expected_programs=3, expected_backends=STANDING_BACKENDS
    )
    snapshot = harness.node_snapshot()

    print("== Refused submissions and unauthenticated mesh traffic ==", flush=True)
    # The mounted command directory could be handed a malformed file, and the
    # node had to refuse it without disturbing anything. The submission is what
    # can be malformed now, and the coordinator is what refuses it, so these
    # cases moved up to the authenticated link. All three leave every node
    # untouched, which `assert_snapshot` checks.
    operator_identity = [
        "--coordinator",
        COORDINATOR,
        "--coord-cert",
        COORDINATOR_CERT,
        "--cert",
        OPERATOR_CERT,
        "--key",
        OPERATOR_KEY,
    ]
    # An identity the coordinator never listed as an operator cannot submit at
    # all: the certificate is the whole authorization the mount used to be.
    harness.assert_submission_refused(
        [
            "submit",
            "--coordinator",
            COORDINATOR,
            "--coord-cert",
            COORDINATOR_CERT,
            "--cert",
            NON_OPERATOR_CERT,
            "--key",
            NON_OPERATOR_KEY,
            "--program",
            harness.programs["single-hb"],
            "--client-slots",
            "1:1",
            "--client",
            "0=/app/ids/clients/cert0.crt",
        ],
        "NotOperator",
        snapshot,
    )
    # A malformed request is refused by the coordinator's own registration
    # table, before any node hears of it.
    harness.assert_submission_refused(
        ["submit", *operator_identity, "--program", "0" * 64, "--client-slots", "1:1"],
        "program hash",
        snapshot,
    )
    # A program no node holds is published and then refused by every node, which
    # must not disturb anything either.
    unknown_program = {
        "name": "unknown-program",
        "program_id": "ab" * 32,
        "backend": "honeybadger",
        "clients": [],
    }
    harness.submit(unknown_program)
    for party in PARTIES:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            refusals = [
                match.group("error")
                for match in (
                    NODE_REFUSED.search(line)
                    for line in harness.logs(party).splitlines()
                )
                if match is not None
                and match.group("execution") == unknown_program["execution_id"]
            ]
            if refusals:
                if "standing startup catalog" not in refusals[-1]:
                    raise AcceptanceFailure(
                        f"{party} refused an unknown program for the wrong reason: {refusals[-1]}"
                    )
                break
            time.sleep(0.2)
        else:
            raise AcceptanceFailure(
                f"{party} did not refuse an execution naming a program it does not hold"
            )
    harness.abort(unknown_program)
    harness.assert_snapshot(snapshot)

    harness.malformed_datagrams()
    harness.assert_snapshot(snapshot)

    # The client-facing listener is reachable by anyone, so who may hold a
    # connection on it is the coordinator's to say: a certificate it admitted
    # nowhere here holds none at all.
    harness.assert_unadmitted_client_certificate_refused()
    # And an admission is not a licence to hold the whole socket: one
    # certificate the coordinator did admit still may not occupy it without
    # bound.
    with harness.probe_certificate_admitted(harness.programs["single-hb"]):
        harness.assert_client_connection_flood_refused()

    print("== Delayed HoneyBadger and AVSS parties ==", flush=True)
    delayed = simple_execution("hb-delayed", harness.programs["single-hb"], 7, 21)
    prepare_and_run(
        harness,
        "fault",
        delayed,
        delayed_party=True,
        unauthorized_probe=True,
    )
    avss = simple_execution(
        "avss-delayed", harness.programs["single-avss"], 6, 18, "avss"
    )
    prepare_and_run(harness, "fault", avss, delayed_party=True)

    print(
        "== Runnable sibling progresses past an absent-client execution ==", flush=True
    )
    run_stalled_sibling(harness)

    print("== One frozen party across two concurrent online executions ==", flush=True)
    online = [
        simple_execution("online-a", harness.programs["slow-hb"], 7, 7),
        simple_execution("online-b", harness.programs["slow-hb"], 11, 11),
    ]
    online_ready = {}
    for item in online:
        harness.submit(item)
        online_ready[item["name"]] = harness.expect_ready(
            item, harness.coordination_seconds + 30
        )
    input_marker = "masked client inputs received"
    party4_inputs = harness.marker_count("party4", input_marker)
    jobs = [harness.start_client("fault", item, item["clients"][0]) for item in online]
    deadline = time.monotonic() + harness.coordination_seconds + 30
    while harness.marker_count("party4", input_marker) < party4_inputs + len(online):
        if time.monotonic() >= deadline:
            raise AcceptanceFailure(
                "party4 did not enter both concurrent online executions"
            )
        time.sleep(0.01)
    for item in online:
        if harness.find_event(
            "party4",
            lambda event, identifier=item["execution_id"]: event["execution_id"]
            == identifier
            and event["event"] in {"completed", "failed", "cancelled"},
        ):
            raise AcceptanceFailure(
                f"{item['name']} became terminal before party4 could be frozen"
            )
    harness.pause("party4")
    try:
        for job in jobs:
            harness.wait_client(job, harness.protocol_seconds + 30)
        online_completed = {}
        for item in online:
            online_completed[item["name"]] = harness.assert_completed(
                item,
                parties=PARTIES[:4],
                timeout=harness.protocol_seconds + 30,
                yield_kind="online",
            )
            for party in PARTIES[:4]:
                online_completed[item["name"]][party]["_ready_at"] = online_ready[
                    item["name"]
                ][party]["at"]
        harness.assert_overlap(online, online_completed, PARTIES[:4])
    finally:
        harness.resume_all()
    for item in online:
        harness.terminal(
            item["execution_id"],
            "party4",
            {"Completed", "Failed", "Cancelled"},
            harness.protocol_seconds + 30,
        )

    print("== Two offline parties fail closed, then the mesh recovers ==", flush=True)
    # The two parties lose the mesh and keep the coordinator. Taking them off
    # the standing network altogether, which is what this phase did when a
    # mounted directory carried the commands, no longer injects this fault: the
    # coordinator is the one path by which a node is told what to run, so a
    # party removed from the network is not an offline party running an
    # execution — it is a party that was never told about one, and the phase
    # would assert the silence rather than the outage. Severing only the peer
    # addresses keeps all five parties admitted, which is what makes the
    # fail-closed assertion below a statement about the mesh.
    harness.sever_peer_links("party3", "party4")
    offline = simple_execution("two-offline", harness.programs["single-hb"], 3, 9)
    failure_started = time.monotonic()
    harness.submit(offline)
    try:
        for party in PARTIES:
            harness.wait_event(
                party,
                lambda event, identifier=offline["execution_id"]: event["execution_id"]
                == identifier
                and event["event"] == "preparing",
                f"admission of {offline['execution_id']}",
                30,
            )
        for party in PARTIES:
            failed = harness.terminal(
                offline["execution_id"],
                party,
                {"Failed"},
                harness.coordination_seconds + 20,
            )
            if failed["event"] != "failed":
                raise AcceptanceFailure(
                    f"an admission with two parties offline did not fail on {party}: {failed}"
                )
    finally:
        harness.restore_peer_links("party3", "party4")
    if time.monotonic() - failure_started > harness.coordination_seconds + 20:
        raise AcceptanceFailure(
            "two-party outage did not fail within the coordination bound"
        )
    time.sleep(3)

    recovery = simple_execution("mesh-recovery", harness.programs["single-hb"], 4, 12)
    prepare_and_run(harness, "fault", recovery)
    harness.assert_snapshot(snapshot)
    print(
        "Adversarial standing mode passed: invalid rosters, refused submissions, "
        "malformed traffic, delayed "
        "HB/AVSS parties, stalled-sibling progress/cancellation, concurrent one-party "
        "online faults, bounded two-party outage, and same-process mesh recovery.",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("campaign", choices=("concurrency", "adversarial"))
    args = parser.parse_args()
    harness = Harness(args.campaign)
    success = False
    try:
        if args.campaign == "concurrency":
            run_concurrency(harness)
        else:
            run_adversarial(harness)
        success = True
        return 0
    except (AcceptanceFailure, subprocess.TimeoutExpired, OSError, ValueError) as error:
        print(f"acceptance failed: {error}", file=sys.stderr)
        return 1
    finally:
        harness.cleanup(success)


if __name__ == "__main__":
    raise SystemExit(main())
