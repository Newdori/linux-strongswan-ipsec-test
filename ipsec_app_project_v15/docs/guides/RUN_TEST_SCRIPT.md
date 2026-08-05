# v15 `run_test.sh` Quick Guide

The wrapper converts short operator commands into the full v15 `ipsec_app` command line while preserving the existing validated test path.

## First-time preparation

```bash
chmod +x run_test.sh
./run_test.sh psk
```

Generate the PSK on only one peer, then copy the exact same `ipsec_test.psk` to the other peer.

## Baseline

```bash
./run_test.sh baseline
./run_test.sh baseline BASE-001
```

## Cross

```bash
./run_test.sh cross
./run_test.sh cross 101 100
```

## Exhaustive IKE only

All 18,172 IKE proposals are generated while ESP remains fixed to the selected config's `esp_proposals`.

```bash
./run_test.sh exhaustive-ike
./run_test.sh exhaustive-ike 101 100
```

## Exhaustive ESP only

All 4,876 ESP proposals are generated while IKE remains fixed to the selected config's `ike_proposals`.

```bash
./run_test.sh exhaustive-esp
./run_test.sh exhaustive-esp 101 100
```

## Complete exhaustive

```bash
./run_test.sh exhaustive
./run_test.sh exhaustive 1001 500
```

The arguments for all generated batch modes are `START LIMIT`. The wrapper defaults to `START=1 LIMIT=100`.

Both peers must use the same mode, START, LIMIT, and corresponding fixed config proposal.

## Custom

```bash
./run_test.sh custom \
  aes256-sha384-prfsha384-ecp384 \
  aes256gcm16
```

Optional custom ID and CHILD KE:

```bash
./run_test.sh custom \
  aes256-sha384-prfsha384-ecp384 \
  aes256-sha256-ecp384 \
  MY-PFS ECP_384
```

Custom matrix:

```bash
./run_test.sh custom-matrix configs/custom_combinations.example.conf
```

## Utility commands

```bash
./run_test.sh count baseline
./run_test.sh count cross
./run_test.sh count exhaustive-ike
./run_test.sh count exhaustive-esp
./run_test.sh count exhaustive

./run_test.sh check baseline
./run_test.sh check exhaustive-ike
./run_test.sh check exhaustive-esp
./run_test.sh cleanup
```

## Config selection

Normally the script detects PC-A or PC-B from the local IPv4 address. To force a config:

```bash
./run_test.sh --config configs/pc_a_initiator.conf exhaustive-ike 1 100
./run_test.sh --config configs/pc_b_responder.conf exhaustive-ike 1 100
```

Run the responder first, then the initiator.

## v15 capture result interpretation

v15 keeps `TESTCASE RESULT`/`overall` as the functional result for compatibility and adds separate result fields:

```text
functional_result
capture_quality_result
strict_result
```

For positive tests, `strict_result=PASS` requires both functional success and lossless/exact packet measurement. This is useful when a long exhaustive run succeeds functionally but tcpdump loses packets on one endpoint.

The supplied endpoint configs use `capture_buffer_kib=16384` in v15. The value remains configurable.
