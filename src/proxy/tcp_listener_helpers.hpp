#pragma once

namespace proxy {
    namespace {
        // Linux accept can report errors from a pending connection or
        // temporary descriptor and kernel buffer exhaustion.
        inline auto transient_accept_error(std::error_code error) noexcept -> bool {
            return error == std::errc::connection_aborted || error == std::errc::interrupted ||
                error == std::errc::network_down || error == std::errc::protocol_error ||
                error == std::errc::no_protocol_option || error == std::errc::host_unreachable ||
                error == std::errc::operation_not_supported || error == std::errc::network_unreachable ||
                error == std::errc::too_many_files_open || error == std::errc::too_many_files_open_in_system ||
                error == std::errc::no_buffer_space || error == std::errc::not_enough_memory ||
                error.default_error_condition() == std::error_condition(EHOSTDOWN, std::generic_category()) ||
                error.default_error_condition() == std::error_condition(ENONET, std::generic_category());
        }

        inline auto listener_endpoint(std::uint16_t port, bool ipv6,
            std::optional<std::array<std::uint8_t, 16>> const& address) -> io::endpoint {
            if (!address)
                return ipv6 ? io::endpoint(io::ipv6_address::loopback(), port)
                            : io::endpoint(io::ipv4_address::loopback(), port);
            if (ipv6) return {io::ipv6_address(*address), port};
            io::ipv4_address::bytes_type bytes{};
            std::copy_n(address->begin(), bytes.size(), bytes.begin());
            return {io::ipv4_address(bytes), port};
        }
    }

    inline auto Server::run_worker_thread(Server* ptr) -> void {
        try {
            while (!stopping.load(std::memory_order_relaxed)) {
                if (drain_requested.load(std::memory_order_acquire)) ptr->begin_drain();
                ptr->poll(std::chrono::milliseconds(20));
                if (!ptr->running) {
                    record_failure(ptr->get_failure().value_or(RuntimeFailure{FailureKind::worker, {}}));
                    failed = true;
                    stopping = true;
                }
            }
            ptr->stop();
        } catch (...) {
            try { record_failure({FailureKind::worker, {}}); } catch (...) {}
            failed = true;
            stopping = true;
            ptr->stop();
        }
    }
}
