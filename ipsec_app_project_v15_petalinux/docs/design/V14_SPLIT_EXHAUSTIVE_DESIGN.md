# v14 Split Exhaustive Mode Design

## Objective

The v12/v13 complete exhaustive mode contains 88,606,672 IKE x ESP pairs. v14 retains that mode but adds two orthogonal modes that isolate one proposal dimension at a time.

## Mode structure

### `exhaustive-ike`

```text
IKE = generated from the complete strongSwan 5.8.4 IKE catalog
ESP = fixed from app_config_t.esp_proposals
```

Current default:

```text
18,172 generated IKE x 1 fixed ESP = 18,172 cases
fixed ESP = aes256-sha256
```

Deterministic IDs:

```text
EXH-I-00001 ... EXH-I-18172
```

If the fixed ESP includes a known PFS KE token, `test_catalog_detect_esp_ke()` enables the existing separate CHILD exchange and expected CHILD KE verification.

### `exhaustive-esp`

```text
IKE = fixed from app_config_t.ike_proposals
ESP = generated from the complete strongSwan 5.8.4 ESP catalog
```

Current default:

```text
1 fixed IKE x 4,876 generated ESP = 4,876 cases
fixed IKE = aes256-sha256-prfsha256-modp2048
```

Deterministic IDs:

```text
EXH-E-0001 ... EXH-E-4876
```

Generated ESP PFS cases retain the existing childless-IKE -> peer barrier -> separate `CREATE_CHILD_SA` -> CHILD KE verification path.

### `exhaustive`

Unchanged full Cartesian product:

```text
18,172 x 4,876 = 88,606,672 cases
```

## Safety

All three exhaustive-family modes require `--limit N` for normal CLI execution. An unbounded run is accepted only when `--allow-full-exhaustive` is explicitly supplied.

`run_test.sh` always supplies a finite limit and defaults to 100 cases.

## Synchronization

Both peers must use:

- identical mode
- identical START
- identical LIMIT
- matching fixed counterpart proposal for split modes

This preserves the deterministic testcase ID/barrier behavior already used by cross and exhaustive modes.

## Compatibility

- strongSwan 5.8.4 remains the minimum catalog.
- No global XFRM flush is introduced.
- Existing baseline/cross/exhaustive/custom semantics are preserved.
- The validated IKE/CHILD/XFRM/UDP/capture data path is not redesigned.
