module logging.sink;
import std;
import proxy.v4;

namespace logging {
    namespace {
        struct SinkGroup {
            std::vector<Sink> sinks;
            auto write(this SinkGroup& self, std::span<SinkRecord const> records) noexcept -> SinkResult {
                SinkResult result;
                for (auto& sink : self.sinks) {
                    auto written = write_batch(sink, records);
                    if (!written && result) result = written;
                }
                return result;
            }
            auto reopen(this SinkGroup& self) noexcept -> SinkResult {
                SinkResult result;
                for (auto& sink : self.sinks) {
                    auto reopened = reopen_sink(sink);
                    if (!reopened && reopened.error() != std::errc::operation_not_supported && result)
                        result = reopened;
                }
                return result;
            }
        };
    }
    auto combine_sinks(std::vector<Sink> sinks) -> Sink {
        if (sinks.empty()) return off_sink();
        if (sinks.size() == 1) return std::move(sinks.front());
        return pro::make_proxy<SinkFacade, SinkGroup>(std::move(sinks));
    }
}
