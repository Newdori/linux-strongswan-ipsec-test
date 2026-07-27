# v13 `run_test.sh` Quick Guide

The wrapper converts short operator commands into the full v13 `ipsec_app` command line while retaining v12 behavior.

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

Default batch: cases 1 through 100.

```bash
./run_test.sh cross
./run_test.sh cross 101 100
```

The arguments are `START LIMIT`. Both peers must use identical values.

## Exhaustive

Default batch: cases 1 through 100.

```bash
./run_test.sh exhaustive
./run_test.sh exhaustive 1001 500
```

The arguments are `START LIMIT`. The wrapper deliberately does not expose unbounded full exhaustive execution as the default path.

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
./run_test.sh count exhaustive
./run_test.sh check baseline
./run_test.sh cleanup
```

## Config selection

Normally the script detects PC-A or PC-B from the local IPv4 address. To force a config:

```bash
./run_test.sh --config configs/pc_a_initiator.conf baseline
./run_test.sh --config configs/pc_b_responder.conf cross 1 100
```

Run the responder first, then the initiator.
