# v10 real-run findings used for v11

Reviewed runs:

- PC-A initiator: `ipsec_matrix_20260724_095007_initiator.zip`
- PC-B responder: `ipsec_matrix_20260724_094941_responder.zip`

## Confirmed good behavior

Both peers executed all 54 enabled positive cases and reported 54 PASS / 0 FAIL.

Across the summary data:

- IKE/CHILD: 54/54 PASS on both peers
- UDP: 54/54 PASS on both peers
- XFRM counter: 54/54 PASS on both peers
- XFRM error: 54/54 PASS on both peers
- Packet Capture: 54/54 PASS on both peers
- SA lifecycle: 54/54 PASS on both peers
- tcpdump kernel drops: 0 on all cases on both peers
- plaintext UDP/9000 observed: 0 cases

The four PFS cases also showed the required CHILD KE token:

```text
ESP-PFS-MODP2048   -> .../MODP_2048
ESP-PFS-ECP256     -> .../ECP_256
ESP-PFS-ECP384     -> .../ECP_384
ESP-PFS-CURVE25519 -> .../CURVE_25519
```

Therefore the v10 PFS correction and the larger tcpdump buffer both worked in the real two-PC test.

## Remaining harness issue: measurement-window alignment

The initiator result happened to have equal aggregate capture/XFRM counts for all cases.  On the responder, 20 cases had a difference between the v10 pcap aggregate count and the XFRM packet delta even though:

- UDP completed normally,
- XFRM error delta stayed zero,
- capture kernel drops stayed zero,
- ESP was visible on wire,
- plaintext UDP was not visible.

This is consistent with v10 taking the XFRM baseline before tcpdump had become ready, so the two counters were not guaranteed to cover exactly the same time interval.

v11 moves capture readiness before the XFRM baseline and adds a capture-stage peer barrier plus a timestamped measurement window.

## Reporting issue

v10 recorded `child_ke=PASS` for non-PFS cases.  That field is now `N/A` unless `separate_child_exchange=true`.

## Multi-SA consideration

v10's XFRM snapshot summed all state counters.  This was not a problem in the isolated 1:1 test, but it is not robust for the planned environment with multiple simultaneous peers/SAs.  v11 therefore scopes packet/byte counters to the tested CHILD reqid.
