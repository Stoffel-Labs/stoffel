# Standing-node Docker acceptance

These tests run five long-lived party containers on one production-shaped
mesh. Each process remains ready until Compose sends SIGTERM; execution IDs are
multiplexed over that mesh rather than creating a mesh or node per program.

The coordinator is the trusted party, and it is what decides what runs: it mints
every execution identity itself and publishes each execution down to the node
roster on `sub_executions`. The driver is an *operator* of the coordinator — it
holds the certificate the coordinator was started with in `--operator-certs` and
submits executions over that authenticated link. Nothing is mounted into a node
to tell it what to run, and no node is configured with an execution identity.

```bash
STOFFEL_COORDINATOR_CONTEXT=/absolute/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/absolute/path/to/stoffel-networking \
docker/test-standing-concurrency.sh

STOFFEL_COORDINATOR_CONTEXT=/absolute/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/absolute/path/to/stoffel-networking \
docker/test-standing-adversarial.sh

STOFFEL_COORDINATOR_CONTEXT=/absolute/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/absolute/path/to/stoffel-networking \
docker/test-standing-all-examples.sh
```

Both source paths must be explicit local Git checkouts. The tests always rebuild the
standing image from the current VM, coordinator, and networking worktrees and
record their revisions and dirty state under the temporary state directory.
The host needs Docker Compose, Git, and Python 3; the driver has no third-party
Python dependencies.
Set `STOFFEL_KEEP_STANDING_STATE=1` to retain that directory. Useful timeout
overrides are `WAIT_TIMEOUT_SECS`, `COORDINATION_TIMEOUT_SECS`, and
`PROTOCOL_TIMEOUT_SECS`.

The Compose stack also supports peer-only latency emulation. For example,
`NET_RTT_MS=100 PARTY3_EXTRA_RTT_MS=250` gives ordinary party pairs about
100 ms RTT and every pair involving party 3 about 350 ms RTT. Extras from two
slow parties are both added: pairwise RTT is `NET_RTT_MS` plus the source and
destination `PARTY<n>_EXTRA_RTT_MS` values. Coordinator and client traffic is
not shaped. Increase the acceptance timeouts above when testing large RTTs.

## Concurrency campaign

One wave admits and starts six executions together:

| Coverage | Cases |
|---|---|
| Same program, same inputs | two HoneyBadger single-client runs with input `7` |
| Same program, different inputs | another run of that artifact with input `4` |
| Multiple programs | single-, multi-, and split-client artifacts |
| Multiple backends | HoneyBadger and AVSS — pinned by `assert_reservoir_backends`, which requires each party's own reservoir-ready lines to report both, so a catalog that stops holding an AVSS artifact fails instead of narrowing the coverage silently |
| Multiple client inputs/outputs | two clients each submit two values and receive distinct two-value results |
| Split client roles | client 0 is input-only; client 1 is output-only |

The driver checks client outputs, execution-scoped destructive preprocessing,
cooperative/online yielding, overlapping execution intervals on all parties,
and unchanged node PIDs. A client-free long/short CPU pair then proves that the
VM yields runnable instruction-heavy work: the short sibling is admitted
second, starts while the long one is already running, and still completes
first. Its starting second is what makes the finishing order evidence of
yielding rather than of a head start, so the driver asserts both. The long
entry is sized in seconds for the same reason: each execution of a wave is
submitted by its own operator call, so the second one is admitted a few hundred
milliseconds after the first, and a long entry shorter than that gap could not
be overtaken however fairly the scheduler yields.

The nodes are next SIGKILLed and restarted with both the durable
admitted-execution index (`--admitted-store`) and all preprocessing volumes
retained. Each restarted process reports, on its startup line and before it has
read anything off the coordinator's stream, how many identities the index it
reopened already holds; the driver requires that number to have grown past the
party's first startup and to account for every identity it watched all five
parties admit, so a republished identity could never re-run against material its
peers already consumed. The refusal itself is pinned by the Rust unit tests
`storage::retired_executions::tests::a_claim_survives_the_process_that_made_it`
and `::a_reopened_index_reports_every_identity_it_retained`, because an operator
cannot name an identity and so cannot construct a replay from here. They then
run nine concurrent executions of the same program with different inputs.

That restart is also the only place any suite reaches an AVSS **partial**
refill. The re-warm sizes every catalog program to `per_execution x
(burst_capacity + 1)`, and the fresh wave's `avss-multi-io` has already drawn
from the AVSS scope with a draw that physically removes, so the parties agree
`TopUp` rather than `Reuse` and enter `top_up_exact` over a reservoir that is
not empty — the one path where the preprocessing pool-clear (design doc §9.1
stage A2) meets inherited material. `assert_agreement_actions` pins that:
`start_nodes(expected_rebuild=False)` already counts rebuilds across all
backends together, but it cannot tell `TopUp` from `Reuse`, and the difference
is the whole subject. Two AVSS executions then draw from what the top-up
produced. Before they existed the retained, post-refill and asymmetric waves
were all HoneyBadger, which left three live checks vacuous for AVSS: the
destructive-allocation digest had no second AVSS digest to differ from, and
`assert_inventory_decreases_between_refills` needs two allocations between
resets to compare anything at all. The first of the two reuses the fresh wave's
inputs exactly, so the cleartext is identical and the allocation digests still
have to differ.

The AVSS draw then keeps going, to nine executions, because that is what
crosses the **elastic** refill's threshold: `availability_reached_refill_threshold`
fires when a scope has fallen to one execution's worth, which from
`per_execution x (burst_capacity + 1)` takes `burst_capacity` allocations — nine
by default. Crossing it drives `spawn_synchronized_reservoir_refill`, a top-up
running concurrently with a live deployment while it holds the program lane. The
driver waits for `RESERVOIR_REFILL_COMPLETED program=<avss>` on every party and
then runs two more executions, so the refilled reservoir is shown serving rather
than merely completing. The nine are submitted three at a time, not nine at
once: what is new here is AVSS meeting a concurrent refill, and the HoneyBadger
block above already covers nine-way concurrency against a refill.

That arm had never run anywhere before, on AVSS or any backend other than
HoneyBadger, so it was added behind a flag, measured, and only then made
unconditional: it passed on its first execution and costs 68 s on a 481 s
campaign (549 s against 481 s, same machine, same images). Recorded here because
a reader who finds it failing later should know it is not a path that has never
worked. Those
reservations cross the reservoir low watermark; every party must refill before
another concurrent pair runs on the same processes. Finally, only party 2's
preprocessing volume is deleted; all five parties must choose rebuild and
complete a fresh execution. This directly covers the retained-state hang,
elastic refill, and asymmetric-store failure modes without rerunning the entire
matrix for every restart.

## Complete example catalog

`test-standing-all-examples.sh` compiles every canonical
`crates/stoffel-lang/examples/**/main.stfl` program, installs the artifacts by
content address, replaces the mounted program directory with that exact catalog,
and warms one execution per program. Independent examples run in concurrent
waves of 16 by default, keeping substantial online overlap on the same five
long-lived party processes without overwhelming the MPC protocol's first-round
progress. Set `STOFFEL_ALL_EXAMPLES_WAVE_SIZE` to select another fan-out; `189`
runs the all-at-once stress/profile shape. The certificate signing fixture is
kept in a final ordered wave so the campaign remains compatible with the
keygen/sign example relationship.

Some examples deliberately use rejection sampling or runtime-sized loops. Their
compiler manifests contain a conservative preprocessing floor with
`dynamic=true`; the catalog campaign opts into those artifacts with
`--allow-dynamic-preprocessing`. Ordinary standing-node startup remains strict
and continues to reject dynamic manifests. The campaign uses a burst capacity
of two and disables the small-fixture triple override so each reservoir follows
the artifact's own demand estimate. Keeping two ready allocations prevents the
one-use catalog warm-up from immediately starting a large background refill
beside the online protocol.

## Adversarial campaign

The fault campaign keeps the same five node processes alive while it verifies:

- missing or slot-mismatched party certificate rosters fail before mesh setup;
- an identity the coordinator does not list as an operator cannot submit an
  execution at all, a malformed submission is refused by the coordinator's own
  registration table, an execution naming a program no node holds is refused by
  every node, cross-party admission mismatches fail before material allocation,
  and malformed QUIC datagrams on both of a node's sockets — the party mesh and
  the client-facing listener — do not kill or reconfigure nodes;
- a valid but unadmitted client certificate is rejected at both of the two
  boundaries it can meet, which are not the same boundary:
  - the coordinator refuses to *associate* it, which is what a client carrying
    inputs reaches. Such a client never dials a party's client socket at all —
    `--client-transport-servers` is read only by an output-only client, and the
    association happens first — so this probe tests the coordinator and not the
    node;
  - every *node* refuses an unadmitted execution route on its client-facing
    listener. Because that listener carries no certificate allowlist, the only
    way to reach it as an adversary is to dial it directly, which the
    `client_listener_probe` example does: it sends the execution route hello for
    a live execution with a certificate that execution does not name, and the
    campaign asserts every party reports the refusal and that no node changed.
    The socket itself admits only certificates the coordinator admitted
    somewhere on that node, so the probe is wrapped in
    `probe_certificate_admitted`, which submits a sibling execution naming the
    probe's certificate and aborts it afterwards — the adversary is a client the
    coordinator did admit, reaching for an execution it has no part in;
- a certificate the coordinator admitted nowhere on a node holds no connection
  on its client-facing listener at all: the probe floods one party while nothing
  admits it, and the party must report refusing every connection as unadmitted
  rather than as over capacity, and stay up;
- an admission is not a licence to hold the whole socket either: the same probe,
  with an admission of its own, opens more connections than a single certificate
  may hold, and the party must report refusing the surplus and stay up;
- a delayed party can rejoin both HoneyBadger and AVSS preparation;
- an execution stalled on an absent client does not block a runnable sibling,
  and cancellation reclaims the stalled execution;
- two concurrent, round-heavy executions and their clients complete on the
  healthy `t=1` quorum while one party is frozen online;
- removing two parties causes bounded, fail-closed preparation; and
- reconnecting those parties permits a fresh execution on the original PIDs.

Docker lifecycle and raw datagrams cannot emulate an authenticated Byzantine
party that forges or equivocates valid MPC payloads. Those cases belong in the
transport/protocol tests or a purpose-built malicious peer; this campaign
validates the production process, certificate, timeout, reconnect, and
execution-isolation boundaries.

## Driver contract

Programs are immutable, content-addressed `.stflb` files. The driver submits
each execution to the coordinator with `stoffel coord-ctl`, which names the
program, the entry point and one certificate-to-slot binding per client; the
coordinator mints the identity, publishes the execution, and the driver learns
the identity from what it submitted. Node lifecycle is then observed in the
nodes' own logs, and each client is bound to the minted identity. Private keys —
including the operator's — are mounted as per-service Compose secrets; the image
contains only public certificates. The operator service also holds one *client*
identity, certificate and key together, so the adversarial campaign can submit
with an identity the coordinator never listed as an operator and have the
coordinator be the party that refuses it: a certificate presented without its
own key is refused locally by TLS and would prove nothing about authorization.

```bash
stoffel coord-ctl submit \
  --coordinator coordinator:31415 --coord-cert /app/ids/server_cert.crt \
  --cert /app/ids/operator/cert.crt --key /run/secrets/stoffel_operator.key \
  --program <content digest> --entry main \
  --client-slots 1:1 --client 0=/var/lib/stoffel/client-certs/cert0.crt
# prints: <execution id> <registration nonce>
```

What the coordinator publishes is a *key*, never certificate material: a
pre-registered client is named by the `subject_public_key` the coordinator
reasons about, and each node resolves that key against the certificate catalog
it froze at startup. A published identity a node holds no certificate for
refuses the whole admission, so a node admits only clients it already knows.

The order of `--client` is the execution-local ordinal the MPC backend numbers
clients by, which is deliberately not the program's slot. `matrix.json`'s
`hb-multi-io` row permutes the two, and that row is the only coverage of the two
index spaces being distinct.

The program manifest is the sole source of the MPC backend, curve, and client
input shape. The matrix keeps backend and curve as fixture metadata only so the
driver can select an artifact and launch a compatible test client; they are not
part of the submission. No matrix row names an execution identity: the
coordinator mints every one.
