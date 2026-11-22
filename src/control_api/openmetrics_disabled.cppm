export module metrics;

import std;
import control_api.types;

export namespace metrics {
    [[nodiscard]] inline auto available() noexcept -> bool { return false; }

    [[nodiscard]] inline auto render_openmetrics(control_api::ControlSnapshot const&) -> std::string {
        return {};
    }
}
