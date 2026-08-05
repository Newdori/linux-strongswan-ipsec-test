# strongSwan 5.8.4 vs 5.9.13 Cryptographic Algorithm Comparison

## 1. Purpose

This document compares the cryptographic algorithms reported by `swanctl --list-algs` on the two interoperability test systems used by this project.

- Reference compatibility version: **strongSwan 5.8.4**
- Peer / newer version: **strongSwan 5.9.13**
- Compatibility rule: algorithms required by the 5.8.4 reference environment must also be usable by 5.9.13.
- Algorithms available only on 5.9.13 are documented but are not mandatory for the 5.8.4-based compatibility matrix.

The provider/plugin shown in brackets, such as `[aes]`, `[aesni]`, `[openssl]`, is the local implementation backend. Interoperability depends primarily on the negotiated IKE/IPsec transform and parameters, not on both peers using the same provider plugin.

Source files:

- `reference/strongswan-5.8.4_list_algs.txt`
- `reference/strongswan-5.9.13_list_algs.txt`

---

## 2. Summary

| Category | 5.8.4 | 5.9.13 | 5.8.4 algorithms missing in 5.9.13 |
|---|---:|---:|---:|
| encryption | 10 | 15 | 0 |
| integrity | 14 | 15 | 0 |
| aead | 4 | 10 | 0 |
| hasher | 12 | 12 | 0 |
| prf | 10 | 10 | 0 |
| xof | 7 | 8 | 0 |
| kdf | 0 | 2 | 0 |
| drbg | 7 | 7 | 0 |
| dh | 23 | 27 | 0 |
| rng | 3 | 3 | 0 |
| nonce-gen | 1 | 1 | 0 |

**Compatibility conclusion from the supplied `--list-algs` outputs:** no algorithm name reported by the 5.8.4 system is absent from the 5.9.13 system.

---

## 3. Encryption

### 3.1 strongSwan 5.8.4

| Algorithm | Provider |
|---|---|
| AES_CBC | aes |
| AES_ECB | aes |
| 3DES_CBC | des |
| DES_CBC | des |
| DES_ECB | des |
| RC2_CBC | rc2 |
| CAMELLIA_CBC | openssl |
| CAST_CBC | openssl |
| BLOWFISH_CBC | openssl |
| NULL | openssl |

### 3.2 strongSwan 5.9.13

| Algorithm | Provider |
|---|---|
| AES_CBC | aesni |
| AES_ECB | aesni |
| AES_CTR | aesni |
| RC2_CBC | rc2 |
| 3DES_CBC | openssl |
| AES_CFB | openssl |
| CAMELLIA_CBC | openssl |
| CAMELLIA_CTR | openssl |
| CAST_CBC | openssl |
| BLOWFISH_CBC | openssl |
| DES_CBC | openssl |
| DES_ECB | openssl |
| NULL | openssl |
| SERPENT_CBC | gcrypt |
| TWOFISH_CBC | gcrypt |

### 3.3 5.9.13-only names

- AES_CTR
- AES_CFB
- CAMELLIA_CTR
- SERPENT_CBC
- TWOFISH_CBC

### 3.4 Provider differences for common algorithms

- AES_CBC: `aes` -> `aesni`
- AES_ECB: `aes` -> `aesni`
- 3DES_CBC: `des` -> `openssl`
- DES_CBC: `des` -> `openssl`
- DES_ECB: `des` -> `openssl`

---

## 4. Integrity

### 4.1 Common algorithms

- HMAC_MD5_96
- HMAC_MD5_128
- HMAC_SHA1_96
- HMAC_SHA1_128
- HMAC_SHA1_160
- HMAC_SHA2_256_128
- HMAC_SHA2_256_256
- HMAC_SHA2_384_192
- HMAC_SHA2_384_384
- HMAC_SHA2_512_256
- HMAC_SHA2_512_512
- CAMELLIA_XCBC_96
- AES_XCBC_96
- AES_CMAC_96

### 4.2 5.9.13-only

- HMAC_SHA2_256_96 `[af-alg]`

### 4.3 Provider differences

- CAMELLIA_XCBC_96: `xcbc` -> `af-alg`
- AES_XCBC_96: `xcbc` -> `aesni`
- AES_CMAC_96: `cmac` -> `aesni`

---

## 5. AEAD

### 5.1 Common algorithms

- AES_GCM_8
- AES_GCM_12
- AES_GCM_16
- CHACHA20_POLY1305

### 5.2 5.9.13-only

- AES_CCM_8
- AES_CCM_12
- AES_CCM_16
- CAMELLIA_CCM_8
- CAMELLIA_CCM_12
- CAMELLIA_CCM_16

### 5.3 Provider differences

- AES_GCM_8/12/16: `openssl` -> `aesni`

---

## 6. Hasher

Both systems report the same names:

- HASH_SHA1
- HASH_SHA2_224
- HASH_SHA2_256
- HASH_SHA2_384
- HASH_SHA2_512
- HASH_MD5
- HASH_MD4
- HASH_SHA3_224
- HASH_SHA3_256
- HASH_SHA3_384
- HASH_SHA3_512
- HASH_IDENTITY

---

## 7. PRF

Both systems report the same names:

- PRF_KEYED_SHA1
- PRF_HMAC_MD5
- PRF_HMAC_SHA1
- PRF_HMAC_SHA2_256
- PRF_HMAC_SHA2_384
- PRF_HMAC_SHA2_512
- PRF_FIPS_SHA1_160
- PRF_AES128_XCBC
- PRF_CAMELLIA128_XCBC
- PRF_AES128_CMAC

Provider implementations differ for several AES-XCBC/CMAC-related entries, but the negotiated algorithm names are common.

---

## 8. XOF

### Common

- XOF_MGF1_SHA1
- XOF_MGF1_SHA224
- XOF_MGF1_SHA256
- XOF_MGF1_SHA384
- XOF_MGF1_SHA512
- XOF_SHAKE128
- XOF_SHAKE256

### 5.9.13-only

- XOF_CHACHA20 `[chapoly]`

---

## 9. KDF

### strongSwan 5.8.4

The supplied `swanctl --list-algs` output does not contain a separate `kdf:` section.

### strongSwan 5.9.13

- KDF_PRF `[openssl]`
- KDF_PRF_PLUS `[openssl]`

This difference must not be interpreted as 5.8.4 being unable to establish IKEv2. Actual project interoperability testing has successfully established IKE and CHILD SAs between 5.8.4 and 5.9.13.

---

## 10. DRBG

Both systems report:

- DRBG_CTR_AES128
- DRBG_CTR_AES192
- DRBG_CTR_AES256
- DRBG_HMAC_SHA1
- DRBG_HMAC_SHA256
- DRBG_HMAC_SHA384
- DRBG_HMAC_SHA512

---

## 11. Diffie-Hellman / Key Exchange

### 11.1 Common algorithms

- MODP_3072
- MODP_4096
- MODP_6144
- MODP_8192
- MODP_2048
- MODP_2048_224
- MODP_2048_256
- MODP_1536
- MODP_1024
- MODP_1024_160
- MODP_768
- MODP_CUSTOM
- ECP_256
- ECP_384
- ECP_521
- ECP_224
- ECP_192
- ECP_256_BP
- ECP_384_BP
- ECP_512_BP
- ECP_224_BP
- CURVE_25519
- CURVE_448

### 11.2 5.9.13-only

- NTRU_112
- NTRU_128
- NTRU_192
- NTRU_256

The NTRU groups are not part of the mandatory 5.8.4-reference compatibility matrix because the supplied 5.8.4 environment does not report them.

---

## 12. RNG

### strongSwan 5.8.4

- RNG_WEAK `[openssl]`
- RNG_STRONG `[random]`
- RNG_TRUE `[random]`

### strongSwan 5.9.13

- RNG_WEAK `[rdrand]`
- RNG_STRONG `[rdrand]`
- RNG_TRUE `[rdrand]`

The RNG algorithm classes are common; the local providers differ.

---

## 13. Nonce Generator

Both systems report:

- NONCE_GEN `[nonce]`

---

## 14. Compatibility Test Policy for This Project

For future versions of the IPsec test application:

1. **strongSwan 5.8.4 remains the compatibility baseline.**
2. Positive compatibility test cases should primarily use transforms available on both 5.8.4 and 5.9.13.
3. 5.9.13-only transforms must be labeled as version-specific and must not be required for a 5.8.4-compatible PASS result.
4. `swanctl --list-algs` indicates charon-side algorithm availability only. ESP compatibility must still be confirmed by actual CHILD SA installation, Linux XFRM state/policy installation, UDP data transfer, XFRM counters/errors, and wire ESP observation.
5. Provider/plugin differences must be recorded but must not automatically be treated as interoperability failures when the negotiated transform is the same.
6. Legacy algorithms such as DES, 3DES, MD5, SHA-1, small MODP groups, CAST and Blowfish should remain separated from the normal recommended crypto matrix and used only for explicit legacy/negative compatibility testing.
7. This comparison document must be reviewed and updated whenever the test PCs, strongSwan versions, loaded plugins, or `--list-algs` output changes.

---

## 15. Project Baseline Conclusion

Based strictly on the two supplied `swanctl --list-algs` outputs:

- Every algorithm name exposed by the **5.8.4** reference system is also represented by the **5.9.13** system.
- 5.9.13 additionally exposes AES-CTR/CFB, Camellia-CTR, Serpent, Twofish, CCM variants, Camellia-CCM, HMAC-SHA2-256-96, XOF-ChaCha20, explicit KDF entries and NTRU groups.
- Therefore, for the current project, **5.8.4 -> 5.9.13 algorithm-name compatibility is not blocked by a missing 5.8.4 algorithm on the 5.9.13 peer**.

