# ipsec_app_project_v11

Automated strongSwan IKEv2/IPsec interoperability and crypto-matrix test application.

Target pair used for the current validation campaign:

- PC-A: `192.168.1.143`, `eth0`, strongSwan 5.9.13, initiator
- PC-B: `192.168.1.144`, `eth0`, strongSwan 5.8.4, responder
- VICI: `unix:///run/charon.vici`
- IKEv2 + PSK
- ESP transport mode by default
- UDP application test port: 9000
- Matrix synchronization port: 9001

Architecture:

```text
Application
  -> swanctl
  -> VICI
  -> charon-systemd
  -> kernel-netlink
  -> Linux XFRM
  -> ESP
```

The application does not link libcharon directly.

## 1. v11 purpose

v10 already passed all 54 enabled cases on both real PCs.  v11 does not replace that working data path.  It improves the precision and scalability of the test harness:

1. tcpdump is ready on both peers before the XFRM baseline is taken.
2. capture timestamps define the same logical traffic window used for result comparison.
3. XFRM packet/byte counters are scoped to the tested CHILD `reqid`, not all SAs on the host.
4. non-PFS `child_ke` is reported as `N/A` instead of a misleading `PASS`.
5. `--case` can explicitly execute one of the five `enabled=false` optional cases.

See `CHANGELOG_V11.md` and `V10_RESULT_FINDINGS.md`.

## 2. Build

```bash
make clean
make
```

Build flags:

```text
-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror
```

## 3. Endpoint configuration

Both supplied endpoint configs contain the v10 capture buffer and the new v11 local guard:

```ini
capture_drain_ms=1000
capture_buffer_kib=4096
measurement_guard_ms=250
capture_enabled=true
cleanup_existing_sa=true
terminate_on_exit=true
```

`measurement_guard_ms` delays only the initiator after its local XFRM baseline.  It is designed to give the responder time to finish its own baseline and enter the UDP receive path without injecting synchronization traffic after the baseline.

## 4. Normal single test

PC-B first:

```bash
sudo ./ipsec_app --config configs/pc_b_responder.conf
```

PC-A:

```bash
sudo ./ipsec_app --config configs/pc_a_initiator.conf
```

## 5. Full crypto matrix

PC-B first:

```bash
sudo ./ipsec_app \
  --config configs/pc_b_responder.conf \
  --matrix configs/crypto_matrix.conf
```

PC-A:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --matrix configs/crypto_matrix.conf
```

The supplied matrix contains:

```text
59 total definitions
54 enabled by default
5 disabled optional/negative/legacy definitions
```

Without `--case`, only the 54 enabled definitions run.

## 6. Run exactly one case

Use the same case ID on both PCs.

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --matrix configs/crypto_matrix.conf \
  --case ESP-GCM-256-16
```

### Explicit disabled-case execution in v11

An explicit `--case` now overrides `enabled=false`.

For example, the tunnel test can be run without editing the matrix:

```bash
--case MODE-TUNNEL
```

The negative negotiation test:

```bash
--case NEG-IKE-NO-MATCH
```

Legacy examples:

```bash
--case LEGACY-3DES-SHA1
--case LEGACY-CAST128
--case LEGACY-BLOWFISH128
```

When no `--case` is provided these five cases remain skipped.

## 7. Positive-case measurement sequence

For a normal positive matrix case v11 uses:

```text
load testcase
  -> CONFIG_READY peer barrier
  -> establish IKE/CHILD
  -> start tcpdump and wait for "listening on <interface>"
  -> CAPTURE_STAGE_READY peer barrier
  -> save strongSwan before snapshot
  -> take reqid-scoped XFRM before snapshot
  -> mark pcap measurement start
  -> initiator measurement_guard_ms
  -> UDP readiness probe / test traffic / ACKs
  -> save strongSwan after snapshot
  -> take reqid-scoped XFRM after snapshot
  -> mark pcap measurement end
  -> capture drain
  -> stop tcpdump
  -> analyze pcap
  -> lifecycle barrier
  -> terminate target SA
  -> verify SA and reqid XFRM removal
```

The `CAPTURE_STAGE_READY` barrier happens before the XFRM baseline, so its ESP packets are excluded from the XFRM delta used for the data test.

## 8. reqid-scoped XFRM measurement

v11 obtains the CHILD reqid from `swanctl --list-sas` and reads:

```bash
ip -d -s xfrm state
```

Only state blocks containing that exact `reqid` contribute to the packet/byte counters.

A typical summary now shows:

```text
xfrm_counter_scope=reqid
xfrm_reqid=1
xfrm_packets_before=...
xfrm_packets_after=...
xfrm_packet_delta=...
```

This avoids unrelated IPsec SAs affecting the tested connection's data-path verdict.

If no reqid is available, the application logs a warning and falls back to all-state counters.  It never flushes other XFRM state/policy entries.

## 9. Capture measurement window

v11 records a microsecond wall-clock interval after the XFRM `before` snapshot and through the XFRM `after` snapshot.

The pcap is decoded with `tcpdump -tt`, and ESP packets with timestamps inside that interval are counted separately:

```text
capture_measurement_window=yes
capture_measurement_esp_packets=<N>
```

When the XFRM counters are reqid-scoped, v11 also records:

```text
capture_xfrm_count_comparable=yes
capture_xfrm_count_match=yes|no
```

This comparison is diagnostic.  It helps identify capture-window or accounting differences without changing the established IPsec Data Path PASS policy.

## 10. tcpdump behavior

The live capture is effectively:

```text
tcpdump --immediate-mode -B 4096 -U -ni eth0 -s 0 -w ... <filter>
```

There is no `-Q out`.

Capture analysis checks:

- outbound ESP exists,
- plaintext UDP/9000 is absent,
- tcpdump statistics were parsed,
- kernel capture drops are zero.

Packet Capture remains diagnostic only.  A capture failure does not turn a valid IKE/CHILD/UDP/XFRM path into an IPsec failure.

## 11. IPsec Data Path PASS

For a positive testcase:

```text
IKE/CHILD ready
AND required CHILD KE verified for PFS testcase
AND UDP success
AND target reqid XFRM packet/byte counters increased
AND global XFRM error total did not increase
```

Overall positive testcase PASS:

```text
IPSEC DATA PATH PASS
AND SA LIFECYCLE PASS
```

## 12. PFS verification retained from v10

The following cases use childless IKE followed by a separate CHILD creation:

```text
ESP-PFS-MODP2048       expected CHILD KE = MODP_2048
ESP-PFS-ECP256         expected CHILD KE = ECP_256
ESP-PFS-ECP384         expected CHILD KE = ECP_384
ESP-PFS-CURVE25519     expected CHILD KE = CURVE_25519
```

Sequence:

```text
IKE only
 -> verify ESTABLISHED with no CHILD
 -> IKE_ONLY_READY barrier
 -> separate CHILD initiate
 -> verify installed CHILD algorithm contains expected KE token
 -> run normal v11 data-path measurement
```

In `matrix_summary.csv`:

```text
PFS case:     child_ke=PASS or FAIL
non-PFS case: child_ke=N/A
```

## 13. SA lifecycle safety

v11 never runs:

```text
ip xfrm state flush
ip xfrm policy flush
```

Cleanup procedure:

```text
find configured app-test SA
 -> terminate only that IKE SA
 -> poll until target IKE/CHILD disappears
 -> verify recorded CHILD reqid has disappeared from XFRM state/policy
```

If the peer already removed the SA, the non-zero terminate return is treated as informational only after actual SA absence is confirmed.

## 14. Matrix CSV fields added/changed in v11

Important fields include:

```text
separate_child_exchange
expected_child_ke
observed_child_algorithms
child_ke
xfrm_counter_scope
xfrm_reqid
capture_packets
capture_received_by_filter
capture_kernel_drops
capture_measurement_esp_packets
capture_xfrm_count_match
xfrm_packet_delta
xfrm_error_delta
```

`capture_xfrm_count_match` is `PASS`, `MISMATCH`, or `N/A`.

## 15. Recommended first v11 real test

Before another complete sweep, run the following on both PCs:

```text
BASE-001
ESP-GCM-256-16
ESP-PFS-ECP384
IKE-CBC-128
```

Check that:

```text
xfrm_counter_scope=reqid
child_ke=N/A for non-PFS
child_ke=PASS for ESP-PFS-ECP384
capture_kernel_drops=0
capture_xfrm_count_match=PASS (preferred diagnostic result)
```

Then run all 54 enabled cases.

After the positive sweep, optional cases can now be invoked directly with `--case` without changing `enabled=false` in the matrix.

## 16. Version compatibility choices

The application continues to avoid `swanctl --list-sas --child`, because the older PC-B strongSwan 5.8.4 does not provide the newer CHILD filter option used by later releases.

The application uses common swanctl operations such as:

```text
--list-sas
--load-conns
--load-creds
--initiate --ike
--initiate --child
--terminate --ike
```

## 17. Credentials

The PSK value is never printed to application logs or matrix CSV files.

Temporary swanctl connection/credential files are created under `/etc/swanctl/`, mode 0600, loaded, and then removed.  Diagnostic saved configuration does not include the secret PSK value.
