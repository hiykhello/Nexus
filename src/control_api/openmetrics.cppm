export module metrics;

import std;
import control_api.types;

export namespace metrics {
    namespace detail {
        auto escape_label(std::string_view input) -> std::string {
            std::string out;
            out.reserve(input.size());
            for (char c : input) {
                if (c == '\\') out += "\\\\";
                else if (c == '"') out += "\\\"";
                else if (c == '\n') out += "\\n";
                else if (static_cast<unsigned char>(c) >= 0x20) out.push_back(c);
            }
            return out;
        }
    }

    [[nodiscard]] inline auto available() noexcept -> bool { return true; }

    // Renders strict OpenMetrics 1.0.0 text using strictly low-cardinality labels
    // (listener index, configured group/mode, fixed outcome enum). Never emits domains,
    // client IPs, ports, URLs, or free-form user strings as labels.
    [[nodiscard]] inline auto render_openmetrics(control_api::ControlSnapshot const& snap) -> std::string {
        std::string out;
        out.reserve(2048);

        out += "# HELP nexus_control_generation Current monotonic control/routing generation.\n";
        out += "# TYPE nexus_control_generation gauge\n";
        out += std::format("nexus_control_generation {}\n", snap.control_generation);

        out += "# HELP nexus_active_sessions Currently active proxy sessions per listener.\n";
        out += "# TYPE nexus_active_sessions gauge\n";
        for (auto const& l : snap.listeners) {
            out += std::format("nexus_active_sessions{{listener=\"{}\"}} {}\n", l.index, l.active_sessions);
        }

        out += "# HELP nexus_traffic_upload_bytes Cumulative uploaded payload bytes per listener.\n";
        out += "# TYPE nexus_traffic_upload_bytes counter\n";
        for (auto const& l : snap.listeners) {
            out += std::format("nexus_traffic_upload_bytes_total{{listener=\"{}\"}} {}\n", l.index, l.upload_bytes);
        }

        out += "# HELP nexus_traffic_download_bytes Cumulative downloaded payload bytes per listener.\n";
        out += "# TYPE nexus_traffic_download_bytes counter\n";
        for (auto const& l : snap.listeners) {
            out += std::format("nexus_traffic_download_bytes_total{{listener=\"{}\"}} {}\n", l.index, l.download_bytes);
        }

        out += "# HELP nexus_outbound_group_members_up Number of healthy members in each outbound group.\n";
        out += "# TYPE nexus_outbound_group_members_up gauge\n";
        out += "# HELP nexus_outbound_group_override Whether an automatic group is manually overridden.\n";
        out += "# TYPE nexus_outbound_group_override gauge\n";
        for (auto const& g : snap.groups) {
            std::size_t up = 0;
            for (auto const& m : g.members) {
                if (m.state == "up") ++up;
            }
            auto gname = detail::escape_label(g.name);
            auto gmode = detail::escape_label(g.mode);
            out += std::format("nexus_outbound_group_members_up{{group=\"{}\",mode=\"{}\"}} {}\n", gname, gmode, up);
            out += std::format("nexus_outbound_group_override{{group=\"{}\",mode=\"{}\"}} {}\n",
                gname, gmode, g.manual_override ? 1 : 0);
        }

        out += "# HELP nexus_control_requests Total control requests by outcome.\n";
        out += "# TYPE nexus_control_requests counter\n";
        out += std::format("nexus_control_requests_total{{outcome=\"authorized\"}} {}\n", snap.authorized_requests);
        out += std::format("nexus_control_requests_total{{outcome=\"unauthorized\"}} {}\n", snap.unauthorized_requests);
        out += std::format("nexus_control_requests_total{{outcome=\"expired\"}} {}\n", snap.expired_requests);

        out += "# EOF\n";
        return out;
    }
}
