#ifndef NEXUS_CORE_C_API_H
#define NEXUS_CORE_C_API_H

#include <stddef.h>

#if defined(_WIN32)
#  if defined(NEXUS_CORE_SHARED)
#    define NEXUS_CORE_EXPORT __declspec(dllexport)
#  else
#    define NEXUS_CORE_EXPORT
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define NEXUS_CORE_EXPORT __attribute__((visibility("default")))
#else
#  define NEXUS_CORE_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// Returns the static core version string.
NEXUS_CORE_EXPORT const char* nexus_core_version(void);

/// Runs the proxy core synchronously with standard `run` arguments (argv[0] is program name).
NEXUS_CORE_EXPORT int nexus_core_run_args(int argc, char* const* argv);

/// Validates a KDL configuration file at `config_path`; returns 0 on success.
NEXUS_CORE_EXPORT int nexus_core_check_config(const char* config_path);

/// Requests graceful shutdown of an active embedded core loop.
NEXUS_CORE_EXPORT void nexus_core_request_stop(void);

/// Requests configuration reload of an active embedded core loop.
NEXUS_CORE_EXPORT void nexus_core_request_reload(void);

/// Returns 1 while `nexus_core_run_args` is active, 0 otherwise.
NEXUS_CORE_EXPORT int nexus_core_is_running(void);

/// Callback invoked for every outbound/DNS socket fd before connecting (Android VpnService.protect).
typedef int (*nexus_protect_fd_fn)(int fd, void* ctx);

/// Callback invoked when the userspace TUN bridge produces an IP packet (iOS NEPacketTunnelProvider).
typedef void (*nexus_packet_output_fn)(const unsigned char* packet, size_t len, void* ctx);

/// Registers or clears (`cb == NULL`) the process-wide socket protection hook.
NEXUS_CORE_EXPORT void nexus_core_set_protect_fd_callback(nexus_protect_fd_fn cb, void* ctx);

/// Registers an external TUN descriptor (`fd < 0` clears). `skip_ioctl` bypasses TUNGETIFF (Android).
NEXUS_CORE_EXPORT void nexus_core_set_tun_fd(int fd, int adopt, int skip_ioctl);

/// Enables or disables the userspace packet bridge for TUN inbounds; returns 0 on success.
NEXUS_CORE_EXPORT int nexus_core_tun_bridge_enable(int enabled, unsigned short mtu,
    nexus_packet_output_fn on_outbound_packet, void* ctx);

/// Injects an inbound raw IP packet from host VPN flow into Nexus; returns 0 on success.
NEXUS_CORE_EXPORT int nexus_core_tun_bridge_inject(const unsigned char* packet, size_t len);

/// Pops an outbound raw IP packet from Nexus when no callback is set; returns 0 (copied), 1 (empty), or <0 on error.
NEXUS_CORE_EXPORT int nexus_core_tun_bridge_pop_outbound(unsigned char* out_buf, size_t capacity, size_t* out_len);

/// Returns a static comma-separated list of compile-time features enabled in this build.
NEXUS_CORE_EXPORT const char* nexus_core_build_features(void);

/// Validates an in-memory KDL configuration string; writes error to `err_buf` on failure; returns 0 on valid.
NEXUS_CORE_EXPORT int nexus_core_check_config_text(const char* kdl_text, char* err_buf, size_t err_cap);

/// Converts external config (`auto`, `clash`, `singbox`, `uri`, `base64`, `sip008`) to Nexus KDL.
/// Sets `*out_len` to exact KDL byte length; returns -4 if `out_buf` is null or `out_cap <= *out_len`.
NEXUS_CORE_EXPORT int nexus_core_convert_config(const char* format, const char* input_text,
    char* out_buf, size_t out_cap, size_t* out_len, char* err_buf, size_t err_cap);

/// Configures or clears (`enabled == 0`) OS system proxy settings; returns 0 on success.
NEXUS_CORE_EXPORT int nexus_core_set_system_proxy(int enabled, const char* host,
    unsigned short http_port, unsigned short socks_port, const char* bypass_csv);

/// Writes compact native Nexus runtime metadata JSON into `out_buf`; returns -4 if buffer too small.
NEXUS_CORE_EXPORT int nexus_core_runtime_info_json(char* out_buf, size_t out_cap, size_t* out_len);

/// Compiles canonical Layer 1 workspace JSON + Layer 3 host JSON into validated KDL 2.0 + JSON result.
/// Sets `*out_len` to exact result JSON byte length; returns -4 if `out_buf` is null or `out_cap <= *out_len`.
/// Returns 0 on valid composition (`ok: true`), -2 on validation/compose errors (structured JSON still written), -1 on bad args.
NEXUS_CORE_EXPORT int nexus_core_compose_workspace(
    const char* workspace_json,
    const char* host_json,
    const char* secrets_dir,
    const char* active_profile_id,
    char* out_buf, size_t out_cap, size_t* out_len,
    char* err_buf, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif
