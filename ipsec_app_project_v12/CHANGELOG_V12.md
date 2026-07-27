# v12 Change Log

Base: validated `ipsec_app_project_v11`.

## New test modes

- `--mode baseline`: retains the validated 54 enabled v11 cases.
- `--mode cross`: generates 30 unique verified IKE proposals x 20 unique verified ESP proposals = 600 cases.
- `--mode exhaustive`: lazily generates the proposal-valid strongSwan 5.8.4 IKE x ESP catalog.
- `--mode custom`: runs an exact user-selected IKE/ESP pair or a user-provided custom matrix.

## Exhaustive generator

- IKE proposals: 18,172.
- ESP proposals: 4,876.
- Complete pairs: 88,606,672.
- Cases are generated lazily; the application does not allocate an 88-million-entry matrix.
- `--start N` and `--limit N` support deterministic batching.
- Full unbounded execution requires explicit `--allow-full-exhaustive`.
- Known ESP PFS proposals automatically use separate CREATE_CHILD_SA verification.

## Operator controls

- `--count-only` prints mode sizes without executing IPsec.
- Direct custom selection: `--ike`, `--esp`, optional `--custom-id`, `--child-ke`.
- `configs/custom_combinations.example.conf` demonstrates multiple selected combinations.

## Reference files

Added CSV versions of the requested 5.8.4 vs 5.9.13 comparison:

- `reference/01_algorithm_category_summary_5.8.4_vs_5.9.13.csv`
- `reference/02_encryption_algorithms_5.8.4_vs_5.9.13.csv`

Also added the exact v12 exhaustive proposal catalog and excluded-loaded-primitives list.

## Preserved v11 behavior

- reqid-scoped XFRM counters.
- capture-ready/XFRM measurement-window alignment.
- PFS childless-IKE + CREATE_CHILD_SA verification.
- target-only SA cleanup; no global XFRM flush.
- capture failure remains diagnostic and separate from IPsec data-path verdict.
- strict `-Wall -Wextra -Wpedantic -Werror` build.
## Simple execution wrapper

- Added executable `run_test.sh`.
- Automatically selects PC-A/PC-B config from the local IPv4 address, with `--config FILE` override.
- `baseline [CASE_ID]` shorthand.
- `cross [START] [LIMIT]` shorthand with safe defaults `1/100`.
- `exhaustive [START] [LIMIT]` shorthand with safe defaults `1/100`.
- `custom IKE ESP [ID] [CHILD_KE]` and `custom-matrix` shorthand.
- `count`, `check`, `cleanup`, and `psk` helper commands.
- Missing PSK is treated as an error for test execution; the wrapper never generates separate peer PSKs automatically.

