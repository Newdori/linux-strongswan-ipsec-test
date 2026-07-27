# ipsec_app_project_v13

Automated strongSwan IKEv2/IPsec interoperability and cryptographic-combination test application.

v13 is based directly on v12. It preserves the validated v11/v12 IKE/CHILD/XFRM/UDP/capture behavior and the v12 baseline/cross/exhaustive/custom generation logic while reorganizing project documentation for Linux/public-repository use.

Target compatibility baseline:

- PC-A: strongSwan 5.9.13, initiator
- PC-B: strongSwan 5.8.4, responder
- VICI: `unix:///run/charon.vici`
- IKEv2 + PSK
- ESP transport mode
- 5.8.4 is the minimum compatibility catalog for exhaustive generation

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

### v13 scope

v13 intentionally does not redesign the proven data path. The release focuses on project organization, version labeling, public-repository hygiene, and regression/static verification while keeping the v12 runtime logic intact.

## 1. v13 test modes

v13 retains the four crypto test modes introduced in v12.

### baseline

Keeps the validated v11 matrix behavior.

```text
54 enabled positive cases
59 total definitions including optional/negative/legacy cases
```

Run both peers with:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode baseline
```

The default matrix is `configs/crypto_matrix.conf`.

Backward-compatible syntax also works:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --matrix configs/crypto_matrix.conf
```

One baseline case:

```bash
--mode baseline --case ESP-GCM-256-16
```

An explicit `--case` still overrides `enabled=false`.

### cross

Builds the Cartesian product of the unique **already validated** IKE and ESP proposals from the enabled baseline matrix.

Current v13 catalog, unchanged from v12 and extracted from the v11 validated matrix:

```text
30 unique validated IKE proposals
20 unique validated ESP proposals
30 x 20 = 600 cross cases
```

Run all 600:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode cross
```

Batch execution:

```bash
--mode cross --start 1 --limit 100
--mode cross --start 101 --limit 100
```

Both peers must use the same `--start` and `--limit` values.

PFS ESP proposals inherited from the baseline automatically use the v10/v11 childless-IKE + separate `CREATE_CHILD_SA` verification path.

### exhaustive

Generates every syntactically valid IKE x ESP combination from the proposal-addressable strongSwan 5.8.4 compatibility catalog retained by v13 from v12.

The generated catalog contains:

```text
IKE classic:
  12 encryption x 9 integrity x 7 PRF x 22 KE = 16,632

IKE AEAD:
  10 AEAD x 7 PRF x 22 KE = 1,540

Total IKE proposals = 18,172

ESP classic:
  12 encryption x 8 integrity x 23 PFS choices x 2 ESN choices = 4,416

ESP AEAD:
  10 AEAD x 23 PFS choices x 2 ESN choices = 460

Total ESP proposals = 4,876

Complete IKE x ESP combinations:
  18,172 x 4,876 = 88,606,672 cases
```

The 23 PFS choices are `none` plus the 22 fixed 5.8.4 key-exchange groups in the v13 proposal catalog inherited from v12.

Because a complete run contains more than 88 million cases, v13 refuses an unbounded exhaustive run by default, preserving the v12 protection.

Recommended batch execution:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode exhaustive \
  --start 1 \
  --limit 100
```

To deliberately run every case:

```bash
--mode exhaustive --allow-full-exhaustive
```

This protection exists to prevent an accidental multi-year test campaign.

**Important:** exhaustive means proposal-valid interoperability inventory, not a security recommendation.  It intentionally includes deprecated algorithms such as 3DES, CAST, Blowfish, MD5, SHA1 and weak DH groups because the purpose is to discover what the 5.8.4/5.9.13 pair actually accepts.  Results for these algorithms must be classified as legacy compatibility results.

`--list-algs` reports charon crypto capability.  It does not guarantee that Linux kernel XFRM supports every ESP transform, so exhaustive cases still require real CHILD installation, UDP traffic, reqid-scoped XFRM counters and ESP capture to PASS.

### custom

Allows the operator to select the exact combination.

Direct single pair:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode custom \
  --ike aes256-sha384-prfsha384-ecp384 \
  --esp aes256gcm16
```

For a PFS ESP proposal, v13 automatically detects known KE keywords using the v12 logic:

```bash
--mode custom \
--ike aes256-sha384-prfsha384-ecp384 \
--esp aes256-sha256-ecp384
```

If a future/custom KE proposal cannot be auto-detected, specify the CHILD algorithm token expected from `swanctl --list-sas`:

```bash
--child-ke ECP_384
```

Optional ID:

```bash
--custom-id MY-AES-GCM-TEST
```

Multiple user-selected combinations can be stored in a matrix file:

```bash
sudo ./ipsec_app \
  --config configs/pc_a_initiator.conf \
  --mode custom \
  --matrix configs/custom_combinations.example.conf
```

## 2. Count cases without running IPsec

`--count-only` does not require root privileges or the strongSwan commands to be running.

```bash
./ipsec_app --config configs/pc_a_initiator.conf --mode baseline --count-only
./ipsec_app --config configs/pc_a_initiator.conf --mode cross --count-only
./ipsec_app --config configs/pc_a_initiator.conf --mode exhaustive --count-only
```

Expected current values:

```text
baseline   54
cross      600
exhaustive 88,606,672
```

## 3. Build

```bash
make clean
make
```

Strict build flags:

```text
-O2 -g -std=c11 -Wall -Wextra -Wpedantic -Werror
```

## 4. v11 measurement/data-path behavior retained

Every positive testcase retains the validated v11 sequence:

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

PFS cases use:

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

Examples:

```text
results/ipsec_matrix_*       baseline/custom-matrix legacy runner
results/ipsec_cross_*        cross mode
results/ipsec_exhaustive_*   exhaustive mode
results/ipsec_custom_*       direct custom mode
```

Every executed case retains the same detailed logs and `matrix_summary.csv` fields used by v11.

## 6. Reference material

`reference/` contains the real uploaded `swanctl --list-algs` outputs and derived comparison files:

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

The first two CSV files are the requested machine-readable versions of:

1. overall algorithm-category comparison between 5.8.4 and 5.9.13
2. detailed encryption algorithm/provider comparison

The exhaustive catalog deliberately distinguishes a loaded crypto primitive from an algorithm that v13 can enumerate as a fixed IKEv2/ESP proposal keyword.

## 7. Security / Git

Never commit the actual PSK:

```text
ipsec_test.psk
```

A `.gitignore` is included for PSKs, private-key material, build outputs, packet captures, logs, archives, credentials/environment files, and test-result directories.

## 8. Operational note

For `cross` and `exhaustive` batch mode, **both peers must run the identical mode, start index and limit** so the existing matrix-control synchronization sees matching deterministic testcase IDs.
## 9. Documentation layout

Only `README.md` remains as the root Markdown document. Historical/change/design/validation/operator documents are organized under:

```text
docs/
├── changelog/
├── design/
├── validation/
└── guides/
```

Key documents:

- [v13 change log](docs/changelog/CHANGELOG_V13.md) — v13 changes
- [v12 mode design](docs/design/V12_MODE_DESIGN.md) — v12 mode-generation design retained by v13
- [algorithm intersection](docs/design/ALGORITHM_INTERSECTION.md) — 5.8.4/5.9.13 compatibility rationale
- [v13 build verification](docs/validation/BUILD_VERIFICATION_V13.txt) — v13 static/build verification
- [run_test.sh guide](docs/guides/RUN_TEST_SCRIPT.md) — wrapper usage guide

The obsolete Windows installation artifact is not part of v13.

## 10. Simple wrapper script

`run_test.sh` is a convenience wrapper for the recommended operator sequence. It auto-selects the PC-A or PC-B config by matching the host IPv4 address against `local_ip` in the two config files. Use `--config FILE` before the command to override auto-detection.

```bash
chmod +x run_test.sh

./run_test.sh baseline
./run_test.sh baseline BASE-001
./run_test.sh cross                 # start=1, limit=100
./run_test.sh cross 101 100
./run_test.sh exhaustive            # start=1, limit=100
./run_test.sh exhaustive 1001 500
./run_test.sh custom aes256-sha384-prfsha384-ecp384 aes256gcm16
./run_test.sh count exhaustive
```

Before a real test, create the PSK once on one peer and copy the identical file to the other peer:

```bash
./run_test.sh psk
```

The wrapper intentionally does not auto-generate a missing PSK during a test, because independently generated PSKs on PC-A and PC-B would cause IKE authentication failure. For `cross` and `exhaustive`, both peers must use the same `START` and `LIMIT`.

See `./run_test.sh --help` for all shorthand commands.

## 11. License and public repository notice

This repository is publicly accessible for **reference and IKEv2/IPsec verification purposes**.

No open-source license is currently granted for this project. Public availability of the source code does not, by itself, grant permission to reproduce, modify, redistribute, sublicense, or commercially use this project beyond rights provided by applicable law or separately granted by the copyright holder.

**All rights reserved by the copyright holder.**

Third-party software and trademarks referenced by this project remain subject to their own license terms. In particular, strongSwan is a separate third-party project used externally through `swanctl`/VICI; this repository does not relicense strongSwan.

