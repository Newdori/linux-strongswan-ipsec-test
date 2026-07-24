# v9 real-run findings used for v10

Input runs reviewed before v10 implementation:

- PC-A initiator: `ipsec_matrix_20260723_072855_initiator`
- PC-B responder: `ipsec_matrix_20260723_162850_responder`

## Data-path finding

Both runs completed all 54 enabled cases successfully for the main IPsec path:

- IKE/CHILD establishment
- UDP request/ACK
- XFRM counter increase
- no XFRM error increase
- target SA lifecycle

The implementation therefore does not redesign the working v9 IKE/ESP path.

## Capture finding

PC-B had actual tcpdump kernel capture drops in two reviewed cases while UDP/XFRM remained normal:

- `IKE-INTEG-256`: 9 packets dropped by kernel
- `IKE-DH-MODP6144`: 4 packets dropped by kernel

This is treated as a packet-capture completeness problem, not an IPsec data-path failure.

v10 responds by adding a configurable tcpdump `-B` buffer and by making kernel-drop statistics explicit in the summary.

## PFS finding

The four v9 `ESP-PFS-*` cases had ESP proposals containing a KE method, but the installed first CHILD status lines did not contain that method. Example v9 CHILD status was of the form:

```text
ESP:AES_CBC-256/HMAC_SHA2_256_128
```

Therefore v9 proved that IPsec still worked with those configurations, but did not prove a separate PFS exchange for the first CHILD.

v10 uses childless IKE and creates the first CHILD separately, then requires the expected KE token in the installed CHILD status.

## Lifecycle finding

A small number of initiator cleanup logs showed `no matching SAs to terminate`, followed by confirmed target-SA and XFRM absence. This is consistent with the peer deleting the shared SA first.

v10 keeps the existing absence verification and reclassifies this known race as informational when the SA is already gone.
