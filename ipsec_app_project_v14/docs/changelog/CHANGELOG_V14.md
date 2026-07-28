# v14 Change Log

Base: `ipsec_app_project_v13`.

v14 is a focused runtime extension that reduces the practical cost of exhaustive interoperability testing while retaining the complete v13 behavior.

## 1. New modes

Added:

- `--mode exhaustive-ike`
  - generates all 18,172 strongSwan 5.8.4 IKE proposals
  - keeps ESP fixed to `esp_proposals` in the selected endpoint config
  - default fixed ESP: `aes256-sha256`
- `--mode exhaustive-esp`
  - generates all 4,876 strongSwan 5.8.4 ESP proposals
  - keeps IKE fixed to `ike_proposals` in the selected endpoint config
  - default fixed IKE: `aes256-sha256-prfsha256-modp2048`

The existing full `exhaustive` mode remains unchanged at 88,606,672 cases.

## 2. Deterministic batching

New modes support:

```text
--start N
--limit N
--count-only
--check
```

Unbounded split-exhaustive execution uses the existing explicit `--allow-full-exhaustive` opt-in protection.

## 3. PFS behavior

- `exhaustive-esp` uses the existing generated-ESP PFS metadata and separate `CREATE_CHILD_SA` verification.
- `exhaustive-ike` checks the configured fixed ESP for a known KE token and uses the same PFS verification path when required.

## 4. Wrapper

`run_test.sh` now supports:

```bash
./run_test.sh exhaustive-ike [START] [LIMIT]
./run_test.sh exhaustive-esp [START] [LIMIT]
./run_test.sh count exhaustive-ike
./run_test.sh count exhaustive-esp
./run_test.sh check exhaustive-ike
./run_test.sh check exhaustive-esp
```

Default batch size remains 100.

## 5. Regression/safety requirements retained

- baseline remains 54 enabled cases
- cross remains 600 cases
- complete exhaustive remains 88,606,672 cases
- custom mode remains available
- strongSwan 5.8.4 remains the minimum compatibility baseline
- no global `ip xfrm state flush` / `ip xfrm policy flush`
- PSK is not intentionally logged
- strict C11 build flags remain `-Wall -Wextra -Wpedantic -Werror`

## 6. Verification status

Static/build/count/catalog verification is recorded in `docs/validation/BUILD_VERIFICATION_V14.txt`.

Real PC-A/PC-B execution of the new split modes has not been performed in the build environment and must be reported separately from implementation/static verification.
