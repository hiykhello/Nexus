#include <cerrno>
#include <stdlib.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
import std;
import logging;
import proxy.v4;
import nexus.thirdparty.glaze;

using logging::Clock;
using logging::Domain;
using logging::Level;
using logging::Submit;
using namespace std::chrono_literals;

static_assert(!std::formattable<logging::Redacted<std::string>, char>);

namespace {
    thread_local std::size_t* allocations = nullptr;
}

auto operator new(std::size_t size) -> void* {
    if (allocations) ++*allocations;
    if (auto pointer = std::malloc(std::max(size, std::size_t{1}))) return pointer;
    throw std::bad_alloc{};
}
auto operator delete(void* pointer) noexcept -> void { std::free(pointer); }
auto operator delete(void* pointer, std::size_t) noexcept -> void { std::free(pointer); }

struct Probe {
    int* calls;
};

template<>
struct std::formatter<Probe, char> {
    constexpr auto parse(std::format_parse_context& context) -> std::format_parse_context::iterator {
        return context.begin();
    }
    auto format(Probe const& value, std::format_context& context) const -> std::format_context::iterator {
        ++*value.calls;
        return std::ranges::copy(std::string_view("probe"), context.out()).out;
    }
};

namespace {
    auto check(bool condition, std::string_view description) -> void {
        if (!condition) {
            std::cerr << "FAIL " << description << '\n';
            std::abort();
        }
    }

    auto start(logging::Sink sink, std::size_t count, logging::Settings settings = {})
        -> std::unique_ptr<logging::Logger> {
        auto result = logging::Logger::start(std::move(sink), count, settings);
        check(result.has_value(), "start logger");
        return std::move(*result);
    }
}

#include "support/logging_sinks.hpp"

namespace {
    struct JsonLine {
        std::int64_t monotonic_ns = 0, wall_epoch_ns = 0;
        std::string level, domain;
        std::uint32_t event_code = 0, worker_id = 0;
        std::uint64_t session_id = 0, generation = 0;
        bool truncated = false;
        std::string timestamp, message;
    };

    auto filter_format_and_json(Temporary const& temporary) -> void {
        auto path = temporary / "events.jsonl";
        auto sink = logging::file_sink({path});
        check(sink.has_value(), "create JSONL sink");
        auto logger = start(std::move(*sink), 1, {{logging::Format::jsonl}});
        auto producer = *logger->producer(0);
        check(!logger->producer(1), "producer bounds");
        int formatted = 0;
        logging::set_level(Level::warn);
        check(producer.log(Domain::dns, Level::info, 1, {}, "{}", Probe{&formatted}) == Submit::filtered &&
              formatted == 0, "global threshold skips formatting");
        logging::set_level(Domain::dns, Level::debug);
        check(logging::get_level(Domain::dns) == Level::debug && logging::get_level(Domain::net) == Level::warn,
              "domain update leaves other watermarks");
        check(producer.log(Domain::net, Level::info, 1, {}, "{}", Probe{&formatted}) == Submit::filtered &&
              producer.log(Domain::dns, Level::debug, 21, {}, "{}", Probe{&formatted}) == Submit::accepted &&
              formatted == 1, "domain threshold selects record");
        logging::set_level(Domain::net, Level::off);
        check(producer.log(Domain::net, Level::fatal, 1, {}, "{}", Probe{&formatted}) == Submit::filtered &&
              producer.log(Domain::dns, Level::off, 1, {}, "{}", Probe{&formatted}) == Submit::filtered &&
              formatted == 1, "off disables emission");
        check(producer.private_text("private.example") == "<redacted>", "default redacts private text");
        auto off = start(logging::off_sink(), 1, {{}, logging::Privacy::verbose});
        check(off->producer(0)->private_text("private.example") == "private.example" &&
              off->producer(0)->log(Domain::dns, Level::error, 1, {}, "{}", Probe{&formatted}) == Submit::filtered &&
              off->drain(Clock::now()).completed, "verbose classification and disabled sink");

        std::string long_text(logging::message_capacity + 80, 'x');
        std::size_t allocations_seen = 0;
        allocations = &allocations_seen;
        auto truncated = producer.log(Domain::dns, Level::warn, 22, {7, 258, 531}, "{}{}", 42, long_text);
        allocations = nullptr;
        check(truncated == Submit::accepted && allocations_seen == 0, "bounded integral/string formatting has zero allocations");
        constexpr char hostile[] = "line\r\n\t\"\\\x1b\0日本\xc2\x85\xe2\x80\xa8\xe2";
        check(producer.log(Domain::dns, Level::error, 23, {}, "{}",
                           std::string_view(hostile, sizeof(hostile) - 1)) == Submit::accepted, "submit escaped UTF-8 and controls");

        auto drained = logger->drain(Clock::now() + 2s);
        check(drained.completed && drained.diagnostics.undrained == 0 && drained.diagnostics.sink_errors == 0 &&
              drained.diagnostics.last_success_ns.has_value(), "observed successful drain and write");
        check(producer.log(Domain::dns, Level::error, 24, {}, "closed") == Submit::closed, "drain closes ingress");
        auto content = slurp(path);
        check(std::ranges::count(content, '\n') == 3 && !content.contains('\r') && !content.contains('\x1b'),
              "one physical line per record");
        std::istringstream input(content);
        std::vector<JsonLine> decoded;
        std::string line;
        while (std::getline(input, line)) {
            JsonLine parsed;
            check(!nex::glaze::read_json(parsed, line), "parse each complete JSON object");
            decoded.push_back(std::move(parsed));
        }
        check(decoded.size() == 3 && decoded[0].message == "probe" && decoded[0].level == "debug" &&
              decoded[1].domain == "dns" && decoded[1].event_code == 22 && decoded[1].worker_id == 7 &&
              decoded[1].session_id == 258 && decoded[1].generation == 531 && decoded[1].truncated &&
              decoded[1].message.size() == logging::message_capacity && decoded[1].message.starts_with("42") &&
              decoded[1].monotonic_ns > 0 && decoded[1].wall_epoch_ns > 0 && decoded[1].timestamp.size() == 30,
              "decoded fields, timestamps and truncation");
        check(decoded[2].message == std::string(hostile, sizeof(hostile) - 2) + "â",
              "decode all escapes and preserve UTF-8, replacing invalid byte with its escaped value");
        logging::set_level(Level::trace);
    }

    struct GatedCapture {
        std::promise<void> entered;
        std::promise<void> released;
        std::future<void> release = released.get_future();
        std::promise<void> drop_report;
        std::string text;
    };

    struct GatedSink {
        GatedCapture* capture;
        bool first = true;
        bool reported = false;
        auto write(this GatedSink& self, std::span<logging::SinkRecord const> lines) noexcept -> logging::SinkResult {
            if (std::exchange(self.first, false)) {
                self.capture->entered.set_value();
                self.capture->release.wait();
            }
            for (auto const& record : lines) {
                auto line = record.line;
                self.capture->text.append(line);
                if (!self.reported && line.contains("log.dropped")) {
                    self.reported = true;
                    self.capture->drop_report.set_value();
                }
            }
            return {};
        }
        auto reopen(this GatedSink&) noexcept -> logging::SinkResult { return {}; }
    };

    auto saturation_and_deadline() -> void {
        GatedCapture capture;
        auto entered = capture.entered.get_future();
        auto sink = pro::make_proxy<logging::SinkFacade, GatedSink>(&capture);
        auto logger = start(std::move(sink), 3, {{logging::Format::text, logging::Timestamp::none}});
        auto first = *logger->producer(0);
        check(first.log(Domain::core, Level::info, 100, {}, "{}",
                        std::string_view("seed\r\n\x1b", 7)) == Submit::accepted, "start in-flight write");
        check(entered.wait_for(2s) == std::future_status::ready, "writer reached sink");

        constexpr auto spare = (logging::queue_capacity * 15 - 1) / 100;
        constexpr auto low_limit = logging::queue_capacity - spare;
        auto saturate = [&](std::size_t index, Domain domain) {
            auto producer = *logger->producer(index);
            for (std::size_t i = 0; i < low_limit; ++i)
                check(producer.log(domain, Level::info, 101, {}, "sample {}", i) == Submit::accepted,
                      "keep low levels until remaining is below 15%");
            int calls = 0;
            for (auto level : {Level::trace, Level::debug, Level::info})
                check(producer.log(domain, level, 102, {}, "{}", Probe{&calls}) == Submit::dropped,
                      "drop low levels before formatting under pressure");
            check(calls == 0, "dropped entries skip formatter");
            for (std::size_t i = 0; i < spare; ++i)
                check(producer.log(domain, i % 2 ? Level::warn : Level::error, 103, {},
                                   "priority {}", i) == Submit::accepted, "accept priority reserve");
            check(producer.log(domain, Level::fatal, 104, {}, "full") == Submit::dropped, "bounded even for fatal");
        };
        std::jthread net(saturate, 1, Domain::net);
        std::jthread dns(saturate, 2, Domain::dns);
        net.join();
        dns.join();

        auto blocked = logger->drain(Clock::now() + 20ms);
        auto& metrics = blocked.diagnostics;
        check(!blocked.completed && metrics.undrained == 2 * logging::queue_capacity + 1 &&
              metrics.queue_high_water[1] == logging::queue_capacity &&
              metrics.queue_high_water[2] == logging::queue_capacity, "deadline snapshots queued and in-flight work");
        for (auto domain : {Domain::net, Domain::dns}) {
            auto const& counts = metrics.dropped[std::to_underlying(domain)];
            check(counts == std::array<std::uint64_t, 6>{1, 1, 1, 0, 0, 1}, "count drops per domain and level");
        }
        capture.released.set_value();
        auto done = logger->drain(Clock::now() + 2s);
        check(done.completed && done.diagnostics.undrained == 0 && done.diagnostics.sink_errors == 0,
              "drain completes after writer resumes");
        check(std::ranges::count(capture.text, '\n') == 2 * logging::queue_capacity + 3 &&
              capture.text.contains("seed\\r\\n\\x1b") && !capture.text.contains('\r') &&
              capture.text.contains("warn net") && capture.text.contains("error dns") &&
              capture.text.contains("log.dropped dropped trace=1 debug=1 info=1 fatal=1"),
              "text escaping, warning/error reserve and drop summary");
    }

    auto periodic_drop_report() -> void {
        GatedCapture capture;
        auto entered = capture.entered.get_future();
        auto reported = capture.drop_report.get_future();
        auto logger = start(pro::make_proxy<logging::SinkFacade, GatedSink>(&capture), 1);
        auto producer = *logger->producer(0);
        check(producer.log(Domain::net, Level::info, 1, {}, "block") == Submit::accepted &&
              entered.wait_for(2s) == std::future_status::ready, "pause writer for periodic report");
        while (producer.log(Domain::net, Level::info, 2, {}, "queued") == Submit::accepted) {}
        capture.released.set_value();
        check(reported.wait_for(3s) == std::future_status::ready, "drop summary delivered without shutdown");
        auto drained = logger->drain(Clock::now() + 2s);
        auto const& counts = drained.diagnostics.dropped[std::to_underlying(Domain::net)];
        check(drained.completed && counts[std::to_underlying(Level::info)] == 1 &&
              capture.text.contains("log.dropped dropped info=1"), "periodic reporting preserves cumulative counts");
    }
}

auto main() -> int {
    Temporary temporary;
    filter_format_and_json(temporary);
    std::println("PASS level/domain, redaction, truncation, allocations, JSONL");
    saturation_and_deadline();
    periodic_drop_report();
    std::println("PASS two saturated producers, priority reserve, periodic/final drop reports, deadline and drain");
    stderr_io(temporary);
    std::println("PASS stderr pipe short write, interrupt, EPIPE, SIGPIPE preservation, file and TTY");
    file_safety_and_rotation(temporary);
    file_reopen(temporary);
    std::println("PASS file permissions, unsafe paths, rotation, reopen and failed reopen");
}
