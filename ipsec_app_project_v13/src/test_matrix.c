#define _POSIX_C_SOURCE 200809L
#include "test_matrix.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char *trim(char *text)
{
    while (*text && isspace((unsigned char)*text)) ++text;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return text;
}

static int copy_value(char *dest, size_t size, const char *value)
{
    if (strlen(value) >= size) return -1;
    strcpy(dest, value);
    return 0;
}

static int parse_bool(const char *value, bool *result)
{
    if (!strcasecmp(value, "true") || !strcmp(value, "1") || !strcasecmp(value, "yes")) {
        *result = true;
        return 0;
    }
    if (!strcasecmp(value, "false") || !strcmp(value, "0") || !strcasecmp(value, "no")) {
        *result = false;
        return 0;
    }
    return -1;
}


static int safe_algorithm_token(const char *value)
{
    if (!value[0]) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (!(isalnum(*p) || *p == '_')) return 0;
    }
    return 1;
}

static void case_defaults(crypto_test_case_t *test_case)
{
    memset(test_case, 0, sizeof(*test_case));
    test_case->enabled = true;
    strcpy(test_case->category, "general");
    strcpy(test_case->expected, "pass");
    strcpy(test_case->ipsec_mode, "transport");
    test_case->separate_child_exchange = false;
}

static int validate_case(const crypto_test_case_t *test_case,
                         char *error, size_t error_size)
{
    if (!test_case->id[0]) {
        snprintf(error, error_size, "matrix case is missing section/id");
        return -1;
    }
    if (!test_case->name[0]) {
        snprintf(error, error_size, "matrix case [%s] is missing name", test_case->id);
        return -1;
    }
    if (!test_case->ike_proposals[0] &&
        (!test_case->ike_initiator[0] || !test_case->ike_responder[0])) {
        snprintf(error, error_size,
                 "matrix case [%s] requires ike_proposals or both role-specific IKE proposals",
                 test_case->id);
        return -1;
    }
    if (!test_case->esp_proposals[0] &&
        (!test_case->esp_initiator[0] || !test_case->esp_responder[0])) {
        snprintf(error, error_size,
                 "matrix case [%s] requires esp_proposals or both role-specific ESP proposals",
                 test_case->id);
        return -1;
    }
    if (strcmp(test_case->ipsec_mode, "transport") != 0 &&
        strcmp(test_case->ipsec_mode, "tunnel") != 0) {
        snprintf(error, error_size, "matrix case [%s] has invalid ipsec_mode", test_case->id);
        return -1;
    }
    if (test_case->separate_child_exchange &&
        !safe_algorithm_token(test_case->expected_child_ke)) {
        snprintf(error, error_size,
                 "matrix case [%s] separate_child_exchange requires expected_child_ke",
                 test_case->id);
        return -1;
    }
    if (strcmp(test_case->expected, "pass") != 0 &&
        strcmp(test_case->expected, "ike_fail") != 0 &&
        strcmp(test_case->expected, "child_fail") != 0) {
        snprintf(error, error_size,
                 "matrix case [%s] expected must be pass, ike_fail or child_fail",
                 test_case->id);
        return -1;
    }
    return 0;
}

int test_matrix_load(const char *path, crypto_test_matrix_t *matrix,
                     char *error, size_t error_size)
{
    memset(matrix, 0, sizeof(*matrix));
    FILE *fp = fopen(path, "r");
    if (!fp) {
        snprintf(error, error_size, "cannot open matrix %s: %s", path, strerror(errno));
        return -1;
    }

    crypto_test_case_t *current = NULL;
    char line[4096];
    int line_number = 0;

    while (fgets(line, sizeof(line), fp)) {
        ++line_number;
        char *text = trim(line);
        if (!*text || *text == '#' || *text == ';') continue;

        size_t len = strlen(text);
        if (text[0] == '[' && len >= 3 && text[len - 1] == ']') {
            if (current && validate_case(current, error, error_size) != 0) {
                fclose(fp);
                return -1;
            }
            if (matrix->count >= TEST_MATRIX_MAX_CASES) {
                snprintf(error, error_size, "matrix exceeds %d cases", TEST_MATRIX_MAX_CASES);
                fclose(fp);
                return -1;
            }
            current = &matrix->cases[matrix->count++];
            case_defaults(current);
            text[len - 1] = '\0';
            if (copy_value(current->id, sizeof(current->id), trim(text + 1)) != 0) {
                snprintf(error, error_size, "%s:%d section id too long", path, line_number);
                fclose(fp);
                return -1;
            }
            continue;
        }

        if (!current) {
            snprintf(error, error_size, "%s:%d key outside a [case] section", path, line_number);
            fclose(fp);
            return -1;
        }

        char *equal = strchr(text, '=');
        if (!equal) {
            snprintf(error, error_size, "%s:%d missing '='", path, line_number);
            fclose(fp);
            return -1;
        }
        *equal = '\0';
        char *key = trim(text);
        char *value = trim(equal + 1);
        int rc = 0;

        if (!strcmp(key, "name")) rc = copy_value(current->name, sizeof(current->name), value);
        else if (!strcmp(key, "enabled")) rc = parse_bool(value, &current->enabled);
        else if (!strcmp(key, "category")) rc = copy_value(current->category, sizeof(current->category), value);
        else if (!strcmp(key, "expected")) rc = copy_value(current->expected, sizeof(current->expected), value);
        else if (!strcmp(key, "ike_proposals")) rc = copy_value(current->ike_proposals, sizeof(current->ike_proposals), value);
        else if (!strcmp(key, "esp_proposals")) rc = copy_value(current->esp_proposals, sizeof(current->esp_proposals), value);
        else if (!strcmp(key, "ike_initiator")) rc = copy_value(current->ike_initiator, sizeof(current->ike_initiator), value);
        else if (!strcmp(key, "ike_responder")) rc = copy_value(current->ike_responder, sizeof(current->ike_responder), value);
        else if (!strcmp(key, "esp_initiator")) rc = copy_value(current->esp_initiator, sizeof(current->esp_initiator), value);
        else if (!strcmp(key, "esp_responder")) rc = copy_value(current->esp_responder, sizeof(current->esp_responder), value);
        else if (!strcmp(key, "ipsec_mode")) rc = copy_value(current->ipsec_mode, sizeof(current->ipsec_mode), value);
        else if (!strcmp(key, "separate_child_exchange")) rc = parse_bool(value, &current->separate_child_exchange);
        else if (!strcmp(key, "expected_child_ke")) rc = copy_value(current->expected_child_ke, sizeof(current->expected_child_ke), value);
        else {
            snprintf(error, error_size, "%s:%d unknown matrix key '%s'", path, line_number, key);
            fclose(fp);
            return -1;
        }

        if (rc != 0) {
            snprintf(error, error_size, "%s:%d invalid/too-long value for '%s'", path, line_number, key);
            fclose(fp);
            return -1;
        }
    }

    if (current && validate_case(current, error, error_size) != 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (matrix->count == 0) {
        snprintf(error, error_size, "matrix contains no test cases");
        return -1;
    }
    return 0;
}

int test_matrix_apply_case(const crypto_test_case_t *test_case,
                           const app_config_t *base,
                           app_config_t *out,
                           char *error, size_t error_size)
{
    *out = *base;
    const char *ike = test_case->ike_proposals;
    const char *esp = test_case->esp_proposals;

    if (base->role == ROLE_INITIATOR) {
        if (test_case->ike_initiator[0]) ike = test_case->ike_initiator;
        if (test_case->esp_initiator[0]) esp = test_case->esp_initiator;
    } else {
        if (test_case->ike_responder[0]) ike = test_case->ike_responder;
        if (test_case->esp_responder[0]) esp = test_case->esp_responder;
    }

    if (copy_value(out->ike_proposals, sizeof(out->ike_proposals), ike) != 0 ||
        copy_value(out->esp_proposals, sizeof(out->esp_proposals), esp) != 0 ||
        copy_value(out->ipsec_mode, sizeof(out->ipsec_mode), test_case->ipsec_mode) != 0) {
        snprintf(error, error_size, "matrix case [%s] is too long for application config", test_case->id);
        return -1;
    }

    /* Matrix cases must be isolated.  Never leave a prior testcase SA/XFRM
     * around to influence the next proposal result. */
    out->cleanup_existing_sa = true;
    out->terminate_on_exit = true;
    out->childless_ike = test_case->separate_child_exchange;
    return app_config_validate(out, error, error_size);
}
