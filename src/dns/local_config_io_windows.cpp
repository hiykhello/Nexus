module dns.local_config;
import std;

namespace dns::detail {
    auto read_local_config_file(std::string_view, std::size_t) -> std::expected<std::string, LocalConfigError> {
        return std::unexpected(LocalConfigError::io_error);
    }
}
