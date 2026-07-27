#include "test_catalog.h"
#include <stdio.h>
#include <string.h>

/*
 * v12 exhaustive catalog policy
 * -----------------------------
 * This catalog intentionally targets proposal-addressable algorithms that are
 * present in the user's strongSwan 5.8.4 --list-algs output and documented as
 * usable IKEv2/ESP proposal keywords.  Algorithms such as AES_ECB, DES_ECB,
 * DES_CBC and RC2_CBC are loaded primitives but are not included in the
 * proposal-addressable exhaustive catalog used here.
 *
 * Deprecated algorithms are included on purpose in exhaustive mode because
 * this mode is an interoperability inventory, not a security recommendation.
 */

static const char *const classic_encryption[] = {
    "3des",
    "cast128",
    "blowfish128",
    "blowfish192",
    "blowfish256",
    "null",
    "aes128",
    "aes192",
    "aes256",
    "camellia128",
    "camellia192",
    "camellia256",
};

static const char *const ike_integrity[] = {
    "md5",
    "md5_128",
    "sha1",
    "sha1_160",
    "aesxcbc",
    "aescmac",
    "sha256",
    "sha384",
    "sha512",
};

/* AES-CMAC is intentionally not in the ESP list because the 5.9 cipher-suite
 * documentation does not list ESP support for that transform. */
static const char *const esp_integrity[] = {
    "md5",
    "md5_128",
    "sha1",
    "sha1_160",
    "aesxcbc",
    "sha256",
    "sha384",
    "sha512",
};

static const char *const ike_prf[] = {
    "prfmd5",
    "prfsha1",
    "prfaesxcbc",
    "prfaescmac",
    "prfsha256",
    "prfsha384",
    "prfsha512",
};

static const char *const aead[] = {
    "aes128gcm8",
    "aes192gcm8",
    "aes256gcm8",
    "aes128gcm12",
    "aes192gcm12",
    "aes256gcm12",
    "aes128gcm16",
    "aes192gcm16",
    "aes256gcm16",
    "chacha20poly1305",
};

static const catalog_ke_t key_exchange[] = {
    {"modp768",      "MODP_768"},
    {"modp1024",     "MODP_1024"},
    {"modp1536",     "MODP_1536"},
    {"modp2048",     "MODP_2048"},
    {"modp3072",     "MODP_3072"},
    {"modp4096",     "MODP_4096"},
    {"modp6144",     "MODP_6144"},
    {"modp8192",     "MODP_8192"},
    {"modp1024s160", "MODP_1024_160"},
    {"modp2048s224", "MODP_2048_224"},
    {"modp2048s256", "MODP_2048_256"},
    {"ecp192",       "ECP_192"},
    {"ecp224",       "ECP_224"},
    {"ecp256",       "ECP_256"},
    {"ecp384",       "ECP_384"},
    {"ecp521",       "ECP_521"},
    {"ecp224bp",     "ECP_224_BP"},
    {"ecp256bp",     "ECP_256_BP"},
    {"ecp384bp",     "ECP_384_BP"},
    {"ecp512bp",     "ECP_512_BP"},
    {"curve25519",   "CURVE_25519"},
    {"curve448",     "CURVE_448"},
};

static const char *const esn_mode[] = {"noesn", "esn"};

#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

size_t exhaustive_ike_count(void)
{
    size_t classic = ARRAY_COUNT(classic_encryption) * ARRAY_COUNT(ike_integrity) *
                     ARRAY_COUNT(ike_prf) * ARRAY_COUNT(key_exchange);
    size_t aead_count = ARRAY_COUNT(aead) * ARRAY_COUNT(ike_prf) *
                        ARRAY_COUNT(key_exchange);
    return classic + aead_count;
}

size_t exhaustive_esp_count(void)
{
    /* PFS dimension contains one "none" value plus every 5.8.4 KE method. */
    size_t pfs_count = ARRAY_COUNT(key_exchange) + 1U;
    size_t classic = ARRAY_COUNT(classic_encryption) * ARRAY_COUNT(esp_integrity) *
                     pfs_count * ARRAY_COUNT(esn_mode);
    size_t aead_count = ARRAY_COUNT(aead) * pfs_count * ARRAY_COUNT(esn_mode);
    return classic + aead_count;
}

size_t exhaustive_pair_count(void)
{
    size_t ike = exhaustive_ike_count();
    size_t esp = exhaustive_esp_count();
    if (ike != 0U && esp > ((size_t)-1) / ike) return 0U;
    return ike * esp;
}

static int format_checked(char *dst, size_t dst_size, const char *fmt,
                          const char *a, const char *b,
                          const char *c, const char *d)
{
    int n = snprintf(dst, dst_size, fmt, a, b, c, d);
    return n >= 0 && (size_t)n < dst_size ? 0 : -1;
}

int exhaustive_ike_at(size_t index, char *proposal, size_t proposal_size)
{
    const size_t enc_n = ARRAY_COUNT(classic_encryption);
    const size_t integ_n = ARRAY_COUNT(ike_integrity);
    const size_t prf_n = ARRAY_COUNT(ike_prf);
    const size_t ke_n = ARRAY_COUNT(key_exchange);
    const size_t classic_n = enc_n * integ_n * prf_n * ke_n;

    if (!proposal || proposal_size == 0U || index >= exhaustive_ike_count()) return -1;

    if (index < classic_n) {
        size_t x = index;
        size_t ke_i = x % ke_n; x /= ke_n;
        size_t prf_i = x % prf_n; x /= prf_n;
        size_t integ_i = x % integ_n; x /= integ_n;
        size_t enc_i = x;
        return format_checked(proposal, proposal_size, "%s-%s-%s-%s",
                              classic_encryption[enc_i], ike_integrity[integ_i],
                              ike_prf[prf_i], key_exchange[ke_i].keyword);
    }

    size_t x = index - classic_n;
    size_t ke_i = x % ke_n; x /= ke_n;
    size_t prf_i = x % prf_n; x /= prf_n;
    size_t aead_i = x;
    return format_checked(proposal, proposal_size, "%s-%s-%s%s",
                          aead[aead_i], ike_prf[prf_i], key_exchange[ke_i].keyword, "");
}

int exhaustive_esp_at(size_t index, char *proposal, size_t proposal_size,
                      bool *separate_child_exchange,
                      char *expected_child_ke, size_t expected_child_ke_size)
{
    const size_t enc_n = ARRAY_COUNT(classic_encryption);
    const size_t integ_n = ARRAY_COUNT(esp_integrity);
    const size_t ke_n = ARRAY_COUNT(key_exchange);
    const size_t pfs_n = ke_n + 1U;
    const size_t esn_n = ARRAY_COUNT(esn_mode);
    const size_t classic_n = enc_n * integ_n * pfs_n * esn_n;

    if (!proposal || proposal_size == 0U || !separate_child_exchange ||
        !expected_child_ke || expected_child_ke_size == 0U ||
        index >= exhaustive_esp_count()) return -1;

    size_t pfs_i;
    size_t esn_i;
    int n;

    if (index < classic_n) {
        size_t x = index;
        esn_i = x % esn_n; x /= esn_n;
        pfs_i = x % pfs_n; x /= pfs_n;
        size_t integ_i = x % integ_n; x /= integ_n;
        size_t enc_i = x;

        if (pfs_i == 0U) {
            n = snprintf(proposal, proposal_size, "%s-%s-%s",
                         classic_encryption[enc_i], esp_integrity[integ_i], esn_mode[esn_i]);
        } else {
            n = snprintf(proposal, proposal_size, "%s-%s-%s-%s",
                         classic_encryption[enc_i], esp_integrity[integ_i],
                         key_exchange[pfs_i - 1U].keyword, esn_mode[esn_i]);
        }
    } else {
        size_t x = index - classic_n;
        esn_i = x % esn_n; x /= esn_n;
        pfs_i = x % pfs_n; x /= pfs_n;
        size_t aead_i = x;
        if (pfs_i == 0U) {
            n = snprintf(proposal, proposal_size, "%s-%s", aead[aead_i], esn_mode[esn_i]);
        } else {
            n = snprintf(proposal, proposal_size, "%s-%s-%s",
                         aead[aead_i], key_exchange[pfs_i - 1U].keyword, esn_mode[esn_i]);
        }
    }

    if (n < 0 || (size_t)n >= proposal_size) return -1;

    if (pfs_i == 0U) {
        *separate_child_exchange = false;
        expected_child_ke[0] = '\0';
    } else {
        *separate_child_exchange = true;
        n = snprintf(expected_child_ke, expected_child_ke_size, "%s",
                     key_exchange[pfs_i - 1U].observed_name);
        if (n < 0 || (size_t)n >= expected_child_ke_size) return -1;
    }
    return 0;
}

bool test_catalog_detect_esp_ke(const char *proposal,
                                char *observed_name, size_t observed_name_size)
{
    if (!proposal || !observed_name || observed_name_size == 0U) return false;
    observed_name[0] = '\0';

    const char *token = proposal;
    while (*token) {
        const char *end = strchr(token, '-');
        size_t token_len = end ? (size_t)(end - token) : strlen(token);
        for (size_t i = 0; i < ARRAY_COUNT(key_exchange); ++i) {
            size_t keyword_len = strlen(key_exchange[i].keyword);
            if (token_len == keyword_len &&
                strncmp(token, key_exchange[i].keyword, token_len) == 0) {
                int n = snprintf(observed_name, observed_name_size, "%s",
                                 key_exchange[i].observed_name);
                return n >= 0 && (size_t)n < observed_name_size;
            }
        }
        if (!end) break;
        token = end + 1;
    }
    return false;
}
