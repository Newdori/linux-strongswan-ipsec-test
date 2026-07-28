# v13 Change Log

Base: `ipsec_app_project_v12`.

v13 is a conservative organization/maintenance release. The validated v11 data path and the v12 baseline/cross/exhaustive/custom test-generation behavior are intentionally preserved.

## 1. Project organization

- Removed the obsolete `WINDOWS_INSTALL.txt` artifact.
- Kept `README.md` at the project root.
- Moved historical change logs to `docs/changelog/`.
- Moved design/algorithm rationale documents to `docs/design/`.
- Moved real-run findings and build/static-verification records to `docs/validation/`.
- Moved the `run_test.sh` operator guide to `docs/guides/`.
- Kept the strongSwan algorithm snapshots and CSV comparison/catalog files under `reference/`.

## 2. Runtime behavior retained

No IKE/CHILD/XFRM/UDP/capture lifecycle redesign was made.

Retained regression behavior includes:

- baseline: 54 enabled cases / 59 total definitions
- cross: 30 verified unique IKE x 20 verified unique ESP = 600 cases
- exhaustive: 18,172 IKE x 4,876 ESP = 88,606,672 cases
- custom direct pair and custom matrix execution
- explicit `--case` execution of disabled baseline cases
- deterministic `--start` / `--limit` batching
- `--allow-full-exhaustive` protection for unbounded exhaustive execution
- PFS verification using a separate CREATE_CHILD_SA exchange
- reqid-scoped XFRM measurement
- capture/XFRM synchronized measurement window
- target-SA/CHILD/reqid selective cleanup only

## 3. Compatibility and safety

- strongSwan 5.8.4 remains the minimum compatibility baseline.
- No global `ip xfrm state flush` or `ip xfrm policy flush` was introduced.
- PSK values remain file-based and are not intentionally printed by the application.
- `.gitignore` continues to exclude PSKs, packet captures, logs, result directories, archives, and private credential/key material.

## 4. Version labeling

Runtime log banners, `run_test.sh` comments, the custom example header, and exhaustive-catalog source comments now identify v13 while preserving the underlying v12 behavior.

## 5. Verification status

- strict C11 build/static verification: see `docs/validation/BUILD_VERIFICATION_V13.txt`
- real PC-A/PC-B regression: not performed in the build container
- therefore baseline/cross/exhaustive/custom runtime status in v13 must be distinguished from the previously completed v11 54/54 real-equipment baseline validation

## 6. Public repository notice

- Added an explicit README notice that the repository may be publicly accessible for reference and verification purposes without granting an open-source license.
- Clarified that public source availability does not itself grant reuse, modification, redistribution, sublicensing, or commercial-use rights beyond applicable law or separate permission from the copyright holder.
- Added an `All rights reserved` notice.
- Clarified that third-party software, including strongSwan, remains subject to its own license terms and is not relicensed by this repository.

