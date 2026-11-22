module;
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>
#include <sys/uio.h>
module logging.sink;
import std;
import proxy.v4;
import logging.core;

namespace logging {
    namespace {
        struct JournalSink {
            auto write(this JournalSink&, std::span<SinkRecord const> records) noexcept -> SinkResult {
                std::error_code failure;
                for (auto const& record : records) {
                    constexpr std::array priorities{"7", "7", "6", "4", "3", "2"};
                    std::array<char, 16> priority;
                    std::array<char, 40> domain, event, generation, worker, session;
                    std::array<char, 4096> message;
                    auto field = [](char* first, char* last) noexcept -> iovec {
                        return {first, static_cast<std::size_t>(last - first)};
                    };
                    auto line = record.line;
                    if (line.ends_with('\n')) line.remove_suffix(1);
                    auto message_end = std::format_to_n(message.data(), message.size(), "MESSAGE={}", line).out;
                    auto priority_end = std::format_to(priority.data(), "PRIORITY={}", priorities[std::to_underlying(record.level)]);
                    auto domain_end = std::format_to(domain.data(), "NEXUS_DOMAIN={}", name(record.domain));
                    auto event_end = std::format_to(event.data(), "NEXUS_EVENT={}", record.event_code);
                    auto generation_end = std::format_to(generation.data(), "NEXUS_GEN={}", record.context.generation);
                    auto worker_end = std::format_to(worker.data(), "NEXUS_WORKER={}", record.context.worker_id);
                    auto session_end = std::format_to(session.data(), "NEXUS_SESSION={}", record.context.session_id);
                    std::array fields{
                        field(message.data(), message_end), field(priority.data(), priority_end),
                        field(domain.data(), domain_end), field(event.data(), event_end),
                        field(generation.data(), generation_end), field(worker.data(), worker_end),
                        field(session.data(), session_end)
                    };
                    auto result = sd_journal_sendv(fields.data(), static_cast<int>(fields.size()));
                    if (result < 0 && !failure) failure = {-result, std::generic_category()};
                }
                if (failure) return std::unexpected(failure);
                return {};
            }
            auto reopen(this JournalSink&) noexcept -> SinkResult { return {}; }
        };
    }

    auto journald_available() noexcept -> bool { return true; }
    auto journald_sink() -> Sink { return pro::make_proxy<SinkFacade, JournalSink>(); }
}
