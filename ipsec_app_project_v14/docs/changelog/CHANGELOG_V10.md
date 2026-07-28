# v10 changes from v9

## Result-driven changes

The real v9 54-case run showed a healthy IPsec data path on both hosts, while exposing three test-harness limitations.

### 1. Real PFS verification

v9 configured KE methods in `esp_proposals`, but the initial CHILD created during IKE_AUTH did not show the KE method in `swanctl --list-sas`.

v10 adds matrix fields:

```ini
separate_child_exchange=true
expected_child_ke=<TOKEN>
```

for all four `ESP-PFS-*` cases.

The PFS flow is now:

```text
childless IKE only
-> confirm no CHILD
-> peer barrier
-> separate CHILD initiation
-> CREATE_CHILD_SA
-> parse installed CHILD algorithms
-> require expected KE token
```

Added strongSwan helpers:

- `strongswan_initiate_ike_only()`
- `strongswan_initiate_child()`
- `strongswan_wait_for_ike()`
- `strongswan_sa_has_child_ke()`

`strongswan_sa_info_t` now records:

- `ike_established`
- installed CHILD algorithm string

### 2. Capture completeness

Added endpoint config:

```ini
capture_buffer_kib=4096
```

Live tcpdump now uses `-B <capture_buffer_kib>` in addition to `--immediate-mode -U`.

The application parses tcpdump's final statistics and records:

- packets captured
- packets received by filter
- packets dropped by kernel

A capture with kernel drops is diagnostic FAIL, but does not fail the IPsec data path or overall testcase.

### 3. Cleanup race classification

If `swanctl --terminate` returns non-zero but an immediate `--list-sas` confirms the target SA is already absent, v10 logs the condition as an informational peer-cleanup race instead of a warning.

Actual SA/XFRM absence is still required.

### 4. CSV/report extensions

Matrix CSV adds:

- `separate_child_exchange`
- `expected_child_ke`
- `observed_child_algorithms`
- `child_ke`
- capture packet statistics/drop count

### 5. Compatibility preserved

- no global XFRM flush
- unfiltered `swanctl --list-sas` parsing retained for strongSwan 5.8.4
- modular C source layout retained
- PSK handling unchanged
- `--case` behavior unchanged
- 59 total matrix definitions / 54 enabled by default
