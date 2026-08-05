# CHANGELOG v15

v15 is a focused reliability update based on v14 real-PC exhaustive test findings.

## Fixed

- Fixed tcpdump statistics parsing for singular output such as `1 packet dropped by kernel`.
- The parser now accepts singular/plural forms for captured, received-by-filter, and dropped-by-kernel counters.

## Improved result reporting

- Added `functional_result`.
- Added `capture_quality_result`.
- Added `strict_result`.
- `strict_result` for positive tests requires functional PASS, capture-quality PASS, a valid measurement window, reqid-scoped comparability, and exact XFRM-to-PCAP ESP packet-count agreement.
- Existing `overall` and `TESTCASE RESULT` retain the v14 functional-result meaning for compatibility.

## Capture tuning

- Raised the default `capture_buffer_kib` from 4096 KiB to 16384 KiB.
- Updated both supplied endpoint configs to use 16384 KiB.
- Added explicit `.gitignore` rules for `ipsec_exhaustive-ike_*/` and `ipsec_exhaustive-esp_*/` result directories.

## Preserved behavior

- Baseline: 54 enabled cases.
- Cross: 600 cases.
- Exhaustive-IKE: 18,172 cases.
- Exhaustive-ESP: 4,876 cases.
- Full exhaustive: 88,606,672 cases.
- Custom mode unchanged.
- strongSwan 5.8.4 remains the minimum compatibility baseline.
- No global XFRM state/policy flush is introduced.
- Existing IKE/CHILD/PFS/ESN/UDP/XFRM/capture/lifecycle workflow is preserved.

## Validation status

Implementation/static verification is complete. v15 has not yet been rerun on the real PC-A/PC-B pair. Therefore the larger capture buffer is not yet claimed to eliminate responder kernel drops.
