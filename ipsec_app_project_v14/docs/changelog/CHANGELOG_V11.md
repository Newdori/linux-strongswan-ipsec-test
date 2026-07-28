# v11 changes from v10

v11 is a measurement-accuracy and multi-SA-safety refinement of v10.  The core IKEv2/IPsec architecture and the 59-case matrix are unchanged.

## 1. Capture/XFRM measurement ordering

v10 took the XFRM `before` snapshot before tcpdump was started.  Real v10 results were functionally clean (54/54 PASS, zero tcpdump kernel drops), but PC-B had a number of cases where the XFRM packet delta and pcap packet count were not identical because the two measurement windows did not start at the same point.

v11 positive-case order is now:

```text
CHILD ready
  -> tcpdump start and "listening on" confirmation
  -> peer CAPTURE_STAGE_READY barrier
  -> XFRM/SA before snapshot
  -> capture measurement-window start marker
  -> initiator local measurement guard
  -> UDP readiness + test traffic
  -> XFRM/SA after snapshot
  -> capture measurement-window end marker
  -> capture drain / stop / analyze
```

The barrier traffic occurs before the XFRM baseline.  `measurement_guard_ms` is local-only and therefore does not inject extra ESP packets after the baseline.

New endpoint setting:

```ini
measurement_guard_ms=250
```

## 2. reqid-scoped XFRM counters

v10 summed packet/byte counters from all Linux XFRM states.  That is sufficient on an isolated test host, but it can be contaminated by unrelated IPsec SAs.

v11 uses the installed CHILD SA `reqid` and sums only XFRM state blocks containing that reqid.  The summary records:

```text
xfrm_counter_scope=reqid
xfrm_reqid=<N>
```

If a CHILD reqid is unexpectedly unavailable, v11 logs a warning and falls back to the previous all-state behavior rather than flushing or modifying unrelated SAs.

## 3. Capture measurement window

v11 records wall-clock start/end markers around the UDP/XFRM measurement interval.  During pcap analysis it counts ESP packets whose pcap timestamp falls inside that interval.

New summary fields:

```text
capture_measurement_window
capture_measurement_esp_packets
capture_xfrm_count_comparable
capture_xfrm_count_match
```

When the XFRM snapshot is reqid-scoped and the capture window is known, v11 compares the pcap ESP count with the reqid-scoped XFRM packet delta.  This is an audit/diagnostic result and does not replace the established IPsec Data Path PASS criteria.

## 4. CHILD KE result semantics

In v10, non-PFS cases were written as `child_ke=PASS` even though no separate CHILD key exchange was being evaluated.

v11 writes:

```text
PFS case:     PASS / FAIL
non-PFS case: N/A
```

The four PFS cases retain the v10 childless-IKE + separate CREATE_CHILD_SA verification.

## 5. Explicit --case can run disabled cases

A v10 usability inconsistency was corrected.

Full matrix execution still skips `enabled=false`, so it runs 54 cases by default.  However an explicit selection now overrides the enabled flag:

```bash
--case MODE-TUNNEL
--case NEG-IKE-NO-MATCH
--case LEGACY-3DES-SHA1
```

This allows the five optional/negative/legacy cases to be tested individually without editing `crypto_matrix.conf`.

## 6. Unchanged safety rules

v11 still never executes:

```text
ip xfrm state flush
ip xfrm policy flush
```

Target SA cleanup remains connection-name based, followed by CHILD reqid disappearance verification.

Packet Capture remains diagnostic.  A capture failure does not turn an otherwise valid IKE/CHILD/UDP/XFRM data path into an IPsec failure.
