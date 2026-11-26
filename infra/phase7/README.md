# Phase 7: evaluation

Blueprint Section 12: attack scenarios, normal-change runs and safety
tests on the NitroTPM cluster, each at least 10 times, with the median and
95th percentile, and a comparison with a binary-verdict baseline.

## Step 7.1: attack scenarios

`evaluate.py` runs the scenarios one run at a time on worker 1 (worker 2
stays clean as the healthy peer) and appends one row per run to
`runs.csv`; the verifier's and controller's evidence for each run is kept
in `raw/<scenario>-<run>/`. `./evaluate.py list` prints every scenario,
what it does and what it should give.

| # | Live action on worker 1 | Expected |
| --- | --- | --- |
| A1 | kubelet changed (one byte appended) and restarted | critical-binary, critical path |
| A2 | containerd changed and restarted | critical-binary, critical path |
| A4 | attestation agent stopped | evidence-missing after 2 minutes, critical path |
| A7 | a changed kernel staged in /boot (no reboot) | boot-file at the next sweep, critical path |
| A8 | /usr/bin/yes changed and run | 90, warning, isolated |
| A9 | unknown binary in /usr/local/bin run | 90, warning, isolated |
| A10 | kubelet and containerd config edited, both restarted | 72.5, degraded, sudden |
| A11 | four config edits 5 minutes apart, each read | 80, warning, gradual |
| A12 | kubelet changed and then frozen (cannot evict) | critical path; pods still move to the other node |
| A13 | runc changed, never run | critical-binary at the next sweep |
| A14 | a binary run from a memfd | refused (vm.memfd_noexec=2), node stays healthy |
| A15 | overlay over /usr/bin in a private mount namespace | mount-overlay, critical path |
| A16 | canary blocked (stands in for a frozen IMA) | ima-canary, critical path |
| A17 | a binary run from /dev/shm, directly and through ld.so | refused (noexec) |

Not run live: A3 (Falco is not in the golden AMI; its critical-file rule
is unit-tested), A5 and A6 (they need an agent that replays an old response
or sends an edited log; covered by the simulator tests and pkg/ima tests).

Measured per run: whether the finding matches, the detection time (from
the moment the changed file was used, worker clock, to the verifier's
finding, verifier clock; both hosts use the Amazon Time Sync Service), the
score, tier and drift class, and for the critical path the time to each
containment step. With two workers the circuit breaker always holds a
critical node (1 of 2 is over 30%), so the runner approves it; isolate,
snapshot, replace and release are timed from that approval. The baseline of
blueprint 12.4 (any mismatch makes the node untrusted, NoExecute) is worked
out from the same findings, as nodes lost per scenario.

After a critical run the quarantined instance is terminated through the
controller (snapshot kept): the account's 8-vCPU limit has no room for the
replacement while it runs. After a score run worker 1 is replaced through
the Auto Scaling group. A14 and A17 leave the node unchanged.

### Run

Cluster up as in Phase 6 (verifier, live controller). Then:

```
cd infra/phase7
./evaluate.py run A9 A1 A14            # a first try, one run each
./evaluate.py run A1 A2 A4 A7 A8 A9 A10 A12 A13 A14 A15 A16 A17 --runs 2
./evaluate.py run A11 --runs 2         # 15 minutes per run
./evaluate.py report                   # writes results.md
```

A run that fails is recorded with result "error" and the runner goes on.

## Trial: 2 runs per scenario (Nov 25-26)

A first pass of every live scenario, 2 runs each (3 for A1, A9 and A14,
which were also in the first try), 30 counted runs. The full results are in
[results.md](results.md); the 10-run campaign comes next.

- Every run gave the expected finding (30 of 30). 15 of the 16 critical
  runs were contained; A15 run 2 was not (see below).
- Critical attacks (A1, A2, A4, A7, A12, A13, A15, A16): found and
  contained (but A15 run 2). Detection median 1 to 5 s, at most about 21 s (where the change
  falls in the 30 s cycle); A4 126 s, which is the 2-minute grace for
  missing evidence plus one cycle. Cordon 1 to 5 s after the finding. After
  the operator's approval: isolated in 0.9 s, evidence snapshot 1.5 s,
  detached 2.0 s, Node object deleted 2.0 s.
- A12: with the kubelet frozen, the 4 pods were running on the other node
  22 s after the approval (run 1; run 2 see below).
- Score attacks: A8 and A9 90 warning isolated, A10 72.5 degraded sudden,
  A11 80 warning gradual. The binary baseline would have lost the node in
  every one of these runs (11 nodes); ours lost none.
- A14 (memfd): refused every time, node stays healthy at 100.
- A17 (/dev/shm): refused both ways every time, but the ld.so attempt is
  still measured (IMA measures the file when ld.so maps it, before the
  noexec check refuses the mapping), so the node goes to 90 warning with
  `unknown:/dev/shm/nt-a17`. Prevented, and the attempt is visible.

### What the trial found

- The network ACL filled up. Isolate adds two deny entries (in and out)
  per quarantined node, and nothing removed them after the node was
  terminated. AWS allows 20 entries per direction, so after about 18
  contained runs A15 run 2 failed with NetworkAclEntryLimitExceeded: the
  node was found, cordoned and tainted NoExecute, but never isolated, and
  the controller retried every 5 s until the runner gave up and
  terminated it. A stale entry is also a risk on its own: a new worker
  that gets the old address would be cut off. Fixed in
  pkg/provider/aws: Terminate removes the instance's entries, and
  Isolate first removes every entry whose address no longer belongs to a
  quarantined instance (terminated elsewhere, or reused by a new worker).
  The controller's IAM policy gains ec2:DeleteNetworkAclEntry. Tested
  with 30 contained nodes in a row on the fake EC2 (2 entries left).
- Two controller fixes from the same run: when a step fails because the
  instance is already terminated, the controller records it as "gone",
  deletes the Node object and stops (it used to retry for ever), and an
  error that repeats every round is recorded once, so it does not push
  the earlier events out of the record (it kept only the last 40, all
  the same error, and the first cause had to be read from the journal).

- A false positive in normal operation. At 00:00 UTC dpkg-db-backup.timer
  copies the package database to /var/backups/*.0 and reads it as root.
  Both workers went to 70 degraded (four unknown files). A12 run 2 fell on
  midnight: its healthy peer was degraded too, its NoSchedule taint kept
  the pods pending, and they did not move within 10 minutes. The four file
  patterns are now runtime in infra/phase2/runtime-policy.json (exact
  names, so a binary dropped into /var/backups is still unknown; tested in
  pkg/imapolicy). The same kind of miss as logrotate in Phase 6: daily
  timers only show up in runs that cross their time.
- Runner bugs, fixed: writing to a running kubelet fails (now copy and
  rename); the controller's state.json and the verifier's status.json grow
  past the 24,000-character SSM output limit after a few runs (the host
  now prints only the entries asked for); step times are taken from the
  controller's own approval event; for A12 and A15 the start time was
  taken after the attack had begun.
- The 8-vCPU limit: when a run failed after containment, the detached
  instance kept its 2 vCPUs, the Auto Scaling group could not launch a
  replacement, and the next two runs timed out waiting for workers (the 2
  runs not counted, besides the first A1 inject). Terminating the instance
  through the controller freed it.
