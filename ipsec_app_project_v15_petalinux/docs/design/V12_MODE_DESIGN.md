# v12 Mode Design

## baseline

Source: `configs/crypto_matrix.conf`.

Purpose: regression baseline.  The 54 previously validated positive cases remain unchanged.

## cross

Source: unique positive/enabled IKE and ESP proposal strings extracted from the baseline matrix at runtime.

Current catalog: 30 IKE x 20 ESP = 600 cases.

This mode answers: "Do independently validated IKE and ESP choices remain interoperable when paired with each other?"

## exhaustive

Source: fixed proposal-addressable catalog based on the supplied strongSwan 5.8.4 `--list-algs` capability plus proposal applicability rules.

The generator separates classic encryption/integrity proposals from AEAD proposals so invalid AEAD+integrity combinations are never generated.

ESP additionally enumerates no-PFS/every fixed KE group and `noesn`/`esn`.

Total: 88,606,672 IKE x ESP pairs.

Because charon capability does not imply kernel ESP support, a generated case is not considered supported until the real CHILD/XFRM/UDP/capture path passes.

## custom

Direct exact pair or a normal matrix file authored by the operator.

This is intended for reproduction, focused regression, newly proposed combinations and future algorithms that are not yet in the built-in exhaustive catalog.
