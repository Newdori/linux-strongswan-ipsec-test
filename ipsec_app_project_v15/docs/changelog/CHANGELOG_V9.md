# v9 changes from v8

## Crypto matrix

- IKE/ESP proposals are no longer hard-coded in `strongswan.c`.
- Added `ike_proposals`, `esp_proposals` and `ipsec_mode` to endpoint configuration.
- Added INI-style `configs/crypto_matrix.conf`.
- Added `src/test_matrix.c` / `include/test_matrix.h`.
- Added `--matrix FILE` and `--case CASE_ID` CLI options.
- Added role-specific proposal fields for negative interoperability tests:
  - `ike_initiator`
  - `ike_responder`
  - `esp_initiator`
  - `esp_responder`
- Matrix mode forces per-case SA isolation (`cleanup_existing_sa=true`, `terminate_on_exit=true`).
- Added CSV summary output.

## Peer testcase synchronization

- Added `matrix_control_port`.
- After both peers load a testcase connection, they synchronize with a UDP config-ready barrier before IKE initiation.
- This prevents the initiator from starting testcase N+1 while the responder is still configured for testcase N.
- The existing post-data lifecycle barrier remains in place before SA termination.

## Capture changes

- `-Q out` remains removed.
- Added `tcpdump --immediate-mode`.
- Added configurable `capture_drain_ms` delay before sending SIGINT to tcpdump.
- tcpdump remains alive through the post-test SA/XFRM snapshot.
- Capture is still diagnostic only and does not decide IPsec Data Path PASS/FAIL.

## Runtime diagnostics

- Every run now saves `swanctl --list-algs` output.
- Generated non-secret connection configuration records the exact IKE/ESP proposal and IPsec mode used by the testcase.

## Safety

- No `ip xfrm state flush` or `ip xfrm policy flush` is used.
- Cleanup still targets only the named IKE/CHILD SA and verifies removal by the recorded CHILD reqid when available.
