# v14 Exhaustive Field Findings Used for v15

## Environment

- Initiator: PC-A, strongSwan 5.9.13
- Responder: PC-B, strongSwan 5.8.4
- v14 split exhaustive modes

## exhaustive-ike

- Functional result: 18,172 / 18,172 PASS.
- Actual IKE algorithm mismatch between peers: 0.
- Bidirectional CHILD SPI mismatch: 0.
- UDP/XFRM/lifecycle functional failures: 0.
- Initiator capture exceptions: 0.
- Responder capture-quality exceptions: 44.
- Responder XFRM-to-PCAP measurement mismatches: 41.
- Actual responder tcpdump kernel-drop cases: 44.
- Several one-packet-drop cases were not represented correctly in v14 summary fields because the parser accepted only the plural tcpdump phrase.

## exhaustive-esp

- Functional result: 4,876 / 4,876 PASS.
- PFS CHILD KE result: 4,664 / 4,664 PASS.
- ESN application: 2,438 / 2,438 matched the configured ESN condition.
- Actual CHILD algorithm mismatch between peers: 0.
- Bidirectional CHILD SPI mismatch: 0.
- UDP/XFRM/lifecycle functional failures: 0.
- Initiator capture exceptions: 0.
- Responder capture-quality exceptions: 11.
- Responder XFRM-to-PCAP measurement mismatches: 10.
- Actual responder tcpdump kernel-drop cases: 11.

## Parser reproduction

Two real v14 responder files contained:

```text
43 packets captured
44 packets received by filter
1 packet dropped by kernel
```

and:

```text
43 packets captured
46 packets received by filter
1 packet dropped by kernel
```

v15's parser fixture test correctly reads both as:

```text
stats_known=yes
packets_dropped_by_kernel=1
lossless=no
```

## Interpretation

The field evidence supports separating functional IPsec success from capture quality. No v14 exhaustive functional failure was identified in these runs; the observed exceptions were responder-side tcpdump/libpcap capture loss.
