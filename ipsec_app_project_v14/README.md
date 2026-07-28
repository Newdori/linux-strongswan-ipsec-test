# ipsec_app_project_v14

Automated strongSwan IKEv2/IPsec interoperability and cryptographic-combination test application.

v14 is based directly on v13. It preserves the validated v11/v12/v13 IKE/CHILD/XFRM/UDP/capture behavior and adds two split exhaustive modes, `exhaustive-ike` and `exhaustive-esp`, so the IKE and ESP compatibility catalogs can be verified independently without immediately expanding to the complete 88,606,672-case Cartesian product.

Target compatibility baseline:

- PC-A: strongSwan 5.9.13, initiator
- PC-B: strongSwan 5.8.4, responder
- VICI: `unix:///run/charon.vici`
- IKEv2 + PSK
- ESP transport mode
- strongSwan 5.8.4 is the minimum compatibility catalog for exhaustive generation

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

## 1. v14 test modes

v14 supports six modes while retaining the existing v13 behavior.

### baseline

Keeps the validated v11 matrix behavior.

```text
54 enabled positive cases
59 total definitions including optional/negative/legacy cases
```

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode baseline
```

The default matrix is `configs/crypto_matrix.conf`.

One baseline case:

```bash
--mode baseline --case BASE-001
```

An explicit `--case` still allows a disabled matrix definition to be selected directly.

### cross

Builds the Cartesian product of unique already-validated IKE and ESP proposals from the enabled baseline matrix.

```text
30 verified IKE proposals
20 verified ESP proposals
30 x 20 = 600 cases
```

```bash
--mode cross --start 1 --limit 100
--mode cross --start 101 --limit 100
```

Both peers must use the same mode, `--start`, and `--limit`.

### exhaustive-ike

Iterates the complete proposal-addressable strongSwan 5.8.4 IKE catalog while keeping ESP fixed to `esp_proposals` from the selected endpoint configuration.

Default PC-A/PC-B configuration:

```text
Generated IKE proposals = 18,172
Fixed ESP proposal      = aes256-sha256
Total cases             = 18,172
```

Catalog composition:

```text
IKE classic: 12 encryption x 9 integrity x 7 PRF x 22 KE = 16,632
IKE AEAD:    10 AEAD x 7 PRF x 22 KE = 1,540
Total IKE = 18,172
```

Recommended execution:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode exhaustive-ike \
  --start 1 \
  --limit 100
```

This mode is useful for identifying IKE proposal compatibility independently of the ESP catalog. If the configured fixed ESP proposal contains a known PFS KE token, the existing childless-IKE + separate `CREATE_CHILD_SA` verification path is retained.

### exhaustive-esp

Iterates the complete proposal-addressable strongSwan 5.8.4 ESP catalog while keeping IKE fixed to `ike_proposals` from the selected endpoint configuration.

Default PC-A/PC-B configuration:

```text
Fixed IKE proposal      = aes256-sha256-prfsha256-modp2048
Generated ESP proposals = 4,876
Total cases             = 4,876
```

Catalog composition:

```text
ESP classic: 12 encryption x 8 integrity x 23 PFS choices x 2 ESN = 4,416
ESP AEAD:    10 AEAD x 23 PFS choices x 2 ESN = 460
Total ESP = 4,876
```

The 23 PFS choices are one no-PFS value plus the 22 fixed 5.8.4 KE groups.

Recommended execution:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode exhaustive-esp \
  --start 1 \
  --limit 100
```

PFS cases automatically use the existing separate `CREATE_CHILD_SA` path and verify the expected CHILD KE from the installed CHILD SA.

### exhaustive

Retains the complete IKE x ESP Cartesian product from v12/v13.

```text
IKE proposals = 18,172
ESP proposals = 4,876
18,172 x 4,876 = 88,606,672 cases
```

Recommended batch execution:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode exhaustive \
  --start 1 \
  --limit 100
```

The application refuses an unbounded run of all exhaustive-family modes unless `--allow-full-exhaustive` is explicitly supplied. This protection applies to `exhaustive-ike`, `exhaustive-esp`, and `exhaustive`.

Example deliberate full run:

```bash
--mode exhaustive-ike --allow-full-exhaustive
--mode exhaustive-esp --allow-full-exhaustive
--mode exhaustive --allow-full-exhaustive
```

The wrapper intentionally uses bounded batches by default.

**Important:** exhaustive modes are interoperability inventories, not security recommendations. Deprecated algorithms such as 3DES, CAST, Blowfish, MD5, SHA1, and weak DH groups are intentionally retained where they are part of the 5.8.4 compatibility catalog.

`swanctl --list-algs` reports charon crypto capability. It does not guarantee that Linux kernel XFRM supports every ESP transform. Final PASS still requires real IKE/CHILD negotiation, XFRM installation, UDP data-path operation, reqid-scoped XFRM counters, and packet capture.

### custom

Direct user-selected pair:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode custom \
  --ike aes256-sha384-prfsha384-ecp384 \
  --esp aes256gcm16
```

PFS example:

```bash
--mode custom \
  --ike aes256-sha384-prfsha384-ecp384 \
  --esp aes256-sha256-ecp384
```

If necessary:

```bash
--child-ke ECP_384
```

Custom matrix execution remains supported through `--mode custom --matrix FILE`.

## 2. Count cases without running IPsec

`--count-only` does not require root privileges or active strongSwan commands.

```bash
./ipsec_app --config configs/pc_a_initiator.conf --mode baseline --count-only
./ipsec_app --config configs/pc_a_initiator.conf --mode cross --count-only
./ipsec_app --config configs/pc_a_initiator.conf --mode exhaustive-ike --count-only
./ipsec_app --config configs/pc_a_initiator.conf --mode exhaustive-esp --count-only
./ipsec_app --config configs/pc_a_initiator.conf --mode exhaustive --count-only
```

Expected values with the current catalog:

```text
baseline        54
cross           600
exhaustive-ike  18,172
exhaustive-esp  4,876
exhaustive      88,606,672
```

For the split modes, count output also prints the fixed counterpart proposal loaded from the endpoint config.

## 3. Build

```bash
make clean
make
```

Strict build flags:

```text
-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror
```

## 4. Validated data-path behavior retained

Every positive testcase retains the established sequence:

```text
load testcase
  -> CONFIG_READY peer barrier
  -> establish IKE/CHILD
  -> start tcpdump; wait for capture ready
  -> CAPTURE_STAGE_READY peer barrier
  -> reqid-scoped XFRM baseline
  -> pcap measurement start
  -> UDP request/ACK traffic
  -> reqid-scoped XFRM after snapshot
  -> pcap measurement end
  -> capture drain/stop/analyze
  -> lifecycle barrier
  -> terminate only the target IKE/CHILD SA
  -> verify target SA and reqid XFRM removal
```

PFS cases retain:

```text
IKE-only
 -> verify childless IKE
 -> IKE_ONLY_READY peer barrier
 -> separate CREATE_CHILD_SA
 -> verify expected CHILD KE
 -> normal data-path measurement
```

No global `ip xfrm state flush` or `ip xfrm policy flush` is used.

## 5. Result directories

```text
results/ipsec_matrix_*          baseline/custom-matrix runner
results/ipsec_cross_*           cross mode
results/ipsec_exhaustive-ike_*  exhaustive-ike mode
results/ipsec_exhaustive-esp_*  exhaustive-esp mode
results/ipsec_exhaustive_*      complete exhaustive mode
results/ipsec_custom_*          direct custom mode
```

Generated case IDs are deterministic between both peers:

```text
EXH-I-00001 ... EXH-I-18172
EXH-E-0001  ... EXH-E-4876
EXH-00000001 ... complete exhaustive catalog
```

## 6. Reference material

`reference/` retains the strongSwan 5.8.4/5.9.13 algorithm snapshots and derived CSV files:

```text
strongswan-5.8.4_list_algs.txt
strongswan-5.9.13_list_algs.txt
STRONGSWAN_CRYPTO_ALGORITHMS_5.8.4_vs_5.9.13.md
01_algorithm_category_summary_5.8.4_vs_5.9.13.csv
02_encryption_algorithms_5.8.4_vs_5.9.13.csv
03_exhaustive_5.8.4_proposal_catalog.csv
04_exhaustive_excluded_loaded_primitives_5.8.4.csv
05_cross_verified_proposals.csv
```

strongSwan 5.8.4 remains the minimum compatibility baseline.

## 7. Security / Git

Never commit the actual PSK or private material.

A `.gitignore` is included for PSKs, private-key material, build outputs, packet captures, logs, archives, credentials/environment files, and test-result directories.

## 8. Operational synchronization

For `cross`, `exhaustive-ike`, `exhaustive-esp`, and `exhaustive`, **both peers must run the identical mode, start index, and limit** so the matrix-control synchronization sees identical deterministic testcase IDs.

For split exhaustive modes, the fixed counterpart proposal in the PC-A and PC-B configs must also match. The supplied PC-A and PC-B configs already use the same defaults.

## 9. Documentation layout

```text
docs/
├── changelog/
├── design/
├── validation/
└── guides/
```

Key documents:

- [v14 change log](docs/changelog/CHANGELOG_V14.md)
- [v14 split exhaustive design](docs/design/V14_SPLIT_EXHAUSTIVE_DESIGN.md)
- [v12 mode design](docs/design/V12_MODE_DESIGN.md)
- [algorithm intersection](docs/design/ALGORITHM_INTERSECTION.md)
- [v14 build verification](docs/validation/BUILD_VERIFICATION_V14.txt)
- [run_test.sh guide](docs/guides/RUN_TEST_SCRIPT.md)

The obsolete Windows installation artifact remains removed.

## 10. Simple wrapper script

```bash
chmod +x run_test.sh

./run_test.sh baseline
./run_test.sh baseline BASE-001
./run_test.sh cross
./run_test.sh cross 101 100
./run_test.sh exhaustive-ike
./run_test.sh exhaustive-ike 101 100
./run_test.sh exhaustive-esp
./run_test.sh exhaustive-esp 101 100
./run_test.sh exhaustive
./run_test.sh exhaustive 1001 500
./run_test.sh custom aes256-sha384-prfsha384-ecp384 aes256gcm16

./run_test.sh count exhaustive-ike
./run_test.sh count exhaustive-esp
./run_test.sh count exhaustive
```

The split/full exhaustive wrapper defaults are `START=1 LIMIT=100`.

Before a real test, create the PSK once on one peer and copy the identical file to the other peer:

```bash
./run_test.sh psk
```

The wrapper never generates a missing PSK automatically during a test.

## 11. License and public repository notice

This repository is publicly accessible for **reference and IKEv2/IPsec verification purposes**.

No open-source license is currently granted for this project. Public availability of the source code does not, by itself, grant permission to reproduce, modify, redistribute, sublicense, or commercially use this project beyond rights provided by applicable law or separately granted by the copyright holder.

**All rights reserved by the copyright holder.**

Third-party software and trademarks referenced by this project remain subject to their own license terms. In particular, strongSwan is a separate third-party project used externally through `swanctl`/VICI; this repository does not relicense strongSwan.
