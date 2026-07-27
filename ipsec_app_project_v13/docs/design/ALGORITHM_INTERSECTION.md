# strongSwan 5.9.13 ↔ 5.8.4 algorithm intersection

Input snapshots:

- `reference/strongswan-5.9.13_list_algs.txt`
- `reference/strongswan-5.8.4_list_algs.txt`

The v11 positive compatibility matrix is based on algorithms that appear on both hosts and that have usable IKE/ESP proposal keywords.

## Common encryption / AEAD relevant to the matrix

Common classic encryption primitives include AES-CBC and Camellia-CBC.  Both hosts also report 3DES, CAST, Blowfish and DES, but these are treated as legacy/weak and are not part of the default positive security sweep.

Common AEAD algorithms:

- AES-GCM ICV 8
- AES-GCM ICV 12
- AES-GCM ICV 16
- ChaCha20-Poly1305

The 5.9.13 host additionally reports AES-CCM and Camellia-CCM, but the 5.8.4 host does not, so CCM is excluded from the cross-version positive matrix.

## Common integrity / PRF

Both hosts report:

- HMAC-SHA2-256
- HMAC-SHA2-384
- HMAC-SHA2-512
- AES-XCBC
- AES-CMAC
- PRF-HMAC-SHA2-256
- PRF-HMAC-SHA2-384
- PRF-HMAC-SHA2-512
- PRF-AES-XCBC
- PRF-AES-CMAC

SHA1/MD5 capabilities are present but are not enabled in the normal test matrix.

## Common key exchange groups

The following useful groups are common:

- MODP 2048, 3072, 4096, 6144, 8192
- ECP 256, 384, 521
- Brainpool ECP 256, 384, 512
- Curve25519
- Curve448

The two hosts also share older groups such as MODP 768/1024/1536 and ECP192.  They are not part of the default security sweep.

NTRU appears only on the 5.9.13 host and is excluded from the cross-version matrix.

## Important interpretation rule

`swanctl --list-algs` reports algorithms available to charon.  It does not prove that the Linux kernel/XFRM implementation can install and process a given ESP transform.  Therefore v11 never marks a testcase PASS based only on the capability list.  Positive cases must still complete:

IKE ESTABLISHED → CHILD INSTALLED → UDP request/ACK → XFRM counter increase → no XFRM error increase.

This distinction is especially important for ESP AEAD, ChaCha20-Poly1305, Camellia and ESN/PFS tests.
