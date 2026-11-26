# Phase 7 results

From 30 runs in runs.csv; times in seconds, median and 95th percentile.

| Scenario | Runs | As expected | Result | Detection (med / p95) | Cordon | Isolate | Release | Nodes lost (ours / binary) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A1 | 3 | 3/3 | critical | 4.0 / 19.2 | 1.9 / 4.5 | 0.9 / 1.0 | 2.0 / 2.1 | 3 / 3 |
| A2 | 2 | 2/2 | critical | 2.4 / 3.6 | 3.8 / 4.7 | 0.9 / 0.9 | 1.9 / 2.0 | 2 / 2 |
| A4 | 2 | 2/2 | critical | 126.2 / 126.3 | 3.9 / 3.9 | 0.9 / 1.0 | 2.0 / 2.1 | 2 / 2 |
| A7 | 1 | 1/1 | critical | 20.2 / 20.2 | 1.8 / 1.8 | 0.9 / 0.9 | 1.9 / 1.9 | 1 / 1 |
| A8 | 2 | 2/2 | score warning | 12.0 / 20.5 |  |  |  | 0 / 2 |
| A9 | 3 | 3/3 | score warning | 4.6 / 19.4 |  |  |  | 0 / 3 |
| A10 | 2 | 2/2 | score degraded | 0.8 / 1.0 |  |  |  | 0 / 2 |
| A11 | 2 | 2/2 | score warning | 5.0 / 5.0 |  |  |  | 0 / 2 |
| A12 | 2 | 2/2 | critical | 1.2 / 1.6 | 3.9 / 4.8 | 0.9 / 0.9 | 1.9 / 2.0 | 2 / 2 |
| A13 | 2 | 2/2 | critical | 3.0 / 4.5 | 3.3 / 3.8 | 0.9 / 1.0 | 2.1 / 2.1 | 2 / 2 |
| A14 | 3 | 3/3 | prevented |  |  |  |  | 0 / 0 |
| A15 | 2 | 2/2 | critical | 2.1 / 3.6 | 2.8 / 2.8 | 1.0 / 1.0 | 2.1 / 2.1 | 1 / 2 |
| A16 | 2 | 2/2 | critical | 4.8 / 7.9 | 3.0 / 4.6 | 0.9 / 1.0 | 1.9 / 2.0 | 2 / 2 |
| A17 | 2 | 2/2 | prevented |  |  |  |  | 0 / 2 |

Not run live:

- A3: Falco is not installed in the golden AMI; the critical-file rule for it is unit-tested (pkg/trust).
- A5: needs an agent that replays an old response; the TLS-bound nonce check is in the simulator tests (pkg/verifier client_sim_test.go).
- A6: needs an agent that sends an edited IMA log; replay mismatch is in pkg/ima tests and `make demo` part 2.

Runs not counted (the runner or the cluster failed, not the scenario):

- A1 run 1: inject-failed: e8/document/orchestration/62b38062-d2c6-4e66-83b0-498f37ee5807/awsrunShellScript/0.awsrunShellScript/_script.sh: 1: cannot create /usr/bin/kubelet: Te
- A14 run 2: error: fewer than two InService workers after 20 minutes
- A7 run 1: error: RuntimeError: fewer than two InService workers after 20 minutes

Detection is from the moment the changed file was used (worker clock) to the verifier's
finding (verifier clock). Cordon is from the finding; isolate and release are from the
operator's approval when the circuit breaker held (two workers: one critical node is 50%).
The binary baseline (blueprint 12.4) marks a node untrusted on any mismatch.
