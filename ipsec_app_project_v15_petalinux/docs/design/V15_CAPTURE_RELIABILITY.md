# v15 Capture Reliability Design

## Purpose

v15 is a focused reliability update based on the completed v14 real-PC `exhaustive-ike` and `exhaustive-esp` runs. It does not change proposal generation, IKE/CHILD negotiation, UDP test traffic, reqid-scoped XFRM accounting, lifecycle cleanup, or the no-global-XFRM-flush policy.

## Field findings that triggered v15

The v14 field runs showed:

- `exhaustive-ike`: 18,172/18,172 functional PASS.
- `exhaustive-esp`: 4,876/4,876 functional PASS.
- Initiator capture was lossless in both runs.
- Responder tcpdump reported 44 capture-quality exceptions in `exhaustive-ike` and 11 in `exhaustive-esp`.
- Some one-packet-drop cases were recorded as `capture_kernel_drops=0` because v14 parsed only the plural tcpdump phrase `packets dropped by kernel`.

These observations indicate a capture/measurement issue rather than an IKE/ESP compatibility failure.

## Change 1: tcpdump singular/plural parser

v15 accepts both forms for all three tcpdump counters:

```text
1 packet captured
N packets captured
1 packet received by filter
N packets received by filter
1 packet dropped by kernel
N packets dropped by kernel
```

This prevents a real one-packet kernel drop from being represented as zero in `matrix_summary.csv`/`result_summary.txt`.

## Change 2: functional, capture-quality, and strict results

The existing `overall` result remains the functional result so existing result consumers do not change behavior.

For positive testcases v15 additionally reports:

- `functional_result`: IKE/CHILD, optional CHILD KE, UDP, reqid-scoped XFRM counters/errors, and lifecycle.
- `capture_quality_result`: capture ready/analysis, outbound ESP observed, no bare plaintext UDP, known tcpdump statistics, and zero kernel drops.
- `strict_result`: functional result plus capture-quality PASS plus a known measurement window and exact reqid-scoped XFRM packet delta == measured ESP packet count.

This makes a case such as `FUNCTIONAL=PASS, CAPTURE=FAIL, STRICT=FAIL` explicit instead of forcing operators to infer the distinction from multiple fields.

Negative/expected-failure cases do not execute the positive measurement path; their strict result follows the expected functional result rather than treating non-applicable capture measurement as failure.

## Change 3: larger default capture buffer

The default and supplied endpoint configs change from:

```text
capture_buffer_kib=4096
```

to:

```text
capture_buffer_kib=16384
```

The setting remains configurable and the existing validation range is unchanged. The change is intended to reduce transient responder-side libpcap/tcpdump kernel-buffer loss observed in the v14 long-running exhaustive tests.

This is an implementation mitigation, not a claimed field fix. A real PC-A/PC-B v15 re-test is required before stating that the drops are eliminated.

## Compatibility

Unchanged:

- strongSwan 5.8.4 minimum compatibility baseline.
- 54-case baseline regression set.
- cross 600 cases.
- exhaustive-ike 18,172 cases.
- exhaustive-esp 4,876 cases.
- full exhaustive 88,606,672 cases.
- custom mode.
- `--start`, `--limit`, `--count-only`, and full-exhaustive protection.
- target-only SA/XFRM cleanup; no global XFRM flush.
- PSK handling and non-disclosure policy.
