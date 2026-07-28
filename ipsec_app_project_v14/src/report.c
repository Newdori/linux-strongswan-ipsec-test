#include "report.h"
#include "process.h"
#include <stdio.h>

static const char *pass_fail(bool value)
{
    return value ? "PASS" : "FAIL";
}

static const char *pass_fail_na(bool evaluated, bool value)
{
    return evaluated ? pass_fail(value) : "N/A";
}

int report_write(const app_config_t *cfg, const char *result_dir,
                 const udp_result_t *udp,
                 const xfrm_snapshot_t *before,
                 const xfrm_snapshot_t *after,
                 const capture_result_t *capture,
                 const test_verdict_t *verdict)
{
    char report[8192];
    const char *capture_status = !capture->enabled ? "DISABLED" : pass_fail(verdict->capture_pass);
    const char *data_path_status = verdict->data_path_evaluated ? pass_fail(verdict->data_path_pass) : "NOT_RUN";

    snprintf(report, sizeof(report),
        "role=%s\nlocal_ip=%s\nremote_ip=%s\ninterface=%s\n"
        "ike_proposals=%s\nesp_proposals=%s\nipsec_mode=%s\n"
        "cleanup_existing_sa=%s\nterminate_on_exit=%s\nchildless_ike=%s\n"
        "ike_child=%s\nchild_ke_result=%s\n"
        "udp_sent=%d\nudp_received=%d\nudp_acknowledgements=%d\nudp_result=%s\n"
        "xfrm_packets_before=%lld\nxfrm_packets_after=%lld\nxfrm_packet_delta=%lld\n"
        "xfrm_bytes_before=%lld\nxfrm_bytes_after=%lld\nxfrm_byte_delta=%lld\n"
        "xfrm_counter_scope=%s\nxfrm_reqid=%u\nxfrm_counter_result=%s\n"
        "xfrm_errors_before=%lld\nxfrm_errors_after=%lld\nxfrm_error_delta=%lld\n"
        "xfrm_error_result=%s\n"
        "ipsec_data_path=%s\n"
        "capture_enabled=%s\ncapture_buffer_kib=%d\nmeasurement_guard_ms=%d\ncapture_ready=%s\ncapture_analysis_ok=%s\n"
        "capture_stats_known=%s\ncapture_packets=%d\ncapture_received_by_filter=%d\n"
        "capture_kernel_drops=%d\ncapture_lossless=%s\n"
        "capture_measurement_window=%s\ncapture_measurement_esp_packets=%d\n"
        "capture_xfrm_count_comparable=%s\ncapture_xfrm_count_match=%s\n"
        "outbound_esp_seen=%s\noutbound_esp_packets=%d\n"
        "plaintext_udp_seen=%s\nplaintext_udp_packets=%d\n"
        "packet_capture=%s\n"
        "sa_lifecycle=%s\n"
        "overall=%s\n",
        app_role_name(cfg->role), cfg->local_ip, cfg->remote_ip, cfg->interface_name,
        cfg->ike_proposals, cfg->esp_proposals, cfg->ipsec_mode,
        cfg->cleanup_existing_sa ? "yes" : "no", cfg->terminate_on_exit ? "yes" : "no",
        cfg->childless_ike ? "force" : "allow",
        verdict->ike_child_ok ? "PASS" : "FAIL",
        pass_fail_na(verdict->child_ke_evaluated, verdict->child_ke_ok),
        udp->sent, udp->received, udp->acknowledgements, pass_fail(verdict->udp_ok),
        before->packets, after->packets, after->packets - before->packets,
        before->bytes, after->bytes, after->bytes - before->bytes,
        before->scoped_to_reqid ? "reqid" : "all-states",
        before->scoped_to_reqid ? before->reqid : 0U,
        pass_fail(verdict->xfrm_counter_ok),
        before->error_total, after->error_total, after->error_total - before->error_total,
        pass_fail(verdict->xfrm_error_ok),
        data_path_status,
        capture->enabled ? "yes" : "no",
        cfg->capture_buffer_kib,
        cfg->measurement_guard_ms,
        capture->ready ? "yes" : "no",
        capture->analysis_ok ? "yes" : "no",
        capture->stats_known ? "yes" : "no",
        capture->packets_captured, capture->packets_received_by_filter,
        capture->packets_dropped_by_kernel, capture->lossless ? "yes" : "no",
        capture->measurement_window_known ? "yes" : "no",
        capture->measurement_total_esp_packets,
        capture->xfrm_capture_count_comparable ? "yes" : "no",
        capture->xfrm_capture_count_comparable ?
            (capture->xfrm_capture_count_match ? "yes" : "no") : "N/A",
        capture->outbound_esp_seen ? "yes" : "no", capture->outbound_esp_packets,
        capture->plaintext_udp_seen ? "yes" : "no", capture->plaintext_udp_packets,
        capture_status,
        pass_fail(verdict->lifecycle_pass),
        pass_fail(verdict->overall_pass));
    char path[1024];
    join_path(path, sizeof(path), result_dir, "result_summary.txt");
    return write_text_file(path, report, 0640);
}
