module logging.sink;

namespace logging {
    auto journald_available() noexcept -> bool { return false; }
    auto journald_sink() -> Sink { return off_sink(); }
}
