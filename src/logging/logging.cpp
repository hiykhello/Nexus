module logging;
import std;
import containers.ring_queue;
import logging.record;

namespace logging {
    namespace {
        constexpr std::uint8_t active = 1;
        constexpr std::uint8_t closed = 2;
        constexpr auto report_interval = std::chrono::seconds(1);

        class Wake {
            std::atomic<bool> pending_{false};
            std::binary_semaphore semaphore_{0};
        public:
            auto signal(this Wake& self) noexcept -> void {
                if (!self.pending_.exchange(true, std::memory_order_acq_rel)) self.semaphore_.release();
            }
            auto wait(this Wake& self, Clock::time_point deadline) -> void {
                if (self.semaphore_.try_acquire_until(deadline))
                    self.pending_.store(false, std::memory_order_release);
            }
        };

        using AtomicDrops = std::array<std::array<std::atomic<std::uint64_t>, level_count>, domain_count>;
    }

    struct ProducerState {
        containers::SpscRingQueue<queue_capacity> queue;
        std::unique_ptr<LogSlot[]> slots{std::make_unique_for_overwrite<LogSlot[]>(queue_capacity)};
        std::atomic<std::uint8_t> gate{0};
        std::atomic<std::size_t> outstanding{0};
        std::atomic<std::size_t> high_water{0};
        AtomicDrops dropped{};
        Wake* wake = nullptr;
    };

    auto Producer::reserve(this Producer const& self, Domain domain, Level level) noexcept
        -> std::expected<LogSlot*, Submit> {
        auto& state = *self.state_;
        std::uint8_t idle = 0;
        if (!state.gate.compare_exchange_strong(idle, active, std::memory_order_acquire))
            return std::unexpected((idle & closed) ? Submit::closed : Submit::busy);

        auto free = state.queue.writable();
        if (free == 0 || (free * 100 < queue_capacity * 15 && level < Level::warn)) {
            state.dropped[std::to_underlying(domain)][std::to_underlying(level)]
                .fetch_add(1, std::memory_order_relaxed);
            auto prior = state.gate.fetch_and(closed, std::memory_order_release);
            if (prior & closed) state.wake->signal();
            return std::unexpected(Submit::dropped);
        }
        state.outstanding.fetch_add(1, std::memory_order_relaxed);
        auto depth = queue_capacity - free + 1;
        if (depth > state.high_water.load(std::memory_order_relaxed))
            state.high_water.store(depth, std::memory_order_relaxed);
        return &state.slots[state.queue.tail()];
    }

    auto Producer::publish(this Producer const& self) noexcept -> void { self.state_->queue.commit(); }

    auto Producer::release(this Producer const& self, bool committed) noexcept -> void {
        auto& state = *self.state_;
        if (!committed) state.outstanding.fetch_sub(1, std::memory_order_relaxed);
        auto prior = state.gate.fetch_and(closed, std::memory_order_release);
        if (committed || (prior & closed)) state.wake->signal();
    }

    struct Logger::Impl {
        Sink sink;
        Settings settings;
        std::size_t count;
        bool active_queues = false;
        std::mutex producer_mutex;
        std::array<std::unique_ptr<ProducerState>, max_producers> owned_producers{};
        std::array<std::atomic<ProducerState*>, max_producers> producers{};
        Wake wake;
        std::thread writer;
        std::mutex control;
        std::condition_variable changed;
        std::atomic<bool> stopping{false};
        bool finished;
        bool reopen_requested = false;
        std::optional<SinkResult> reopen_result;
        std::atomic<std::uint64_t> sink_errors{0};
        std::atomic<std::int64_t> last_success_ns{0};
        DropCounts reported{};
        std::size_t next_producer = 0;
        mutable std::mutex ring_mutex;
        std::deque<LogRingEntry> ring;
        std::uint64_t next_seq = 0;
        std::uint64_t evicted = 0;

        Impl(Sink selected, std::size_t size, Settings options)
            : sink(std::move(selected)), settings(options), count(size),
              active_queues(static_cast<bool>(sink) || options.ring_capacity != 0),
              finished(!active_queues) {}

        auto get_or_create_producer(this Impl& self, std::size_t index) noexcept -> ProducerState* {
            if (!self.active_queues || index >= self.count) return nullptr;
            if (auto* existing = self.producers[index].load(std::memory_order_acquire)) return existing;
            std::lock_guard lock(self.producer_mutex);
            if (auto* existing = self.producers[index].load(std::memory_order_relaxed)) return existing;
            try {
                auto created = std::make_unique<ProducerState>();
                created->wake = &self.wake;
                if (self.stopping.load(std::memory_order_acquire))
                    created->gate.store(closed, std::memory_order_relaxed);
                auto* raw = created.get();
                self.owned_producers[index] = std::move(created);
                self.producers[index].store(raw, std::memory_order_release);
                return raw;
            } catch (...) {
                return nullptr;
            }
        }

        auto diagnostics(this Impl const& self) noexcept -> Diagnostics {
            Diagnostics result;
            result.producer_count = self.count;
            result.sink_errors = self.sink_errors.load(std::memory_order_relaxed);
            auto last = self.last_success_ns.load(std::memory_order_relaxed);
            if (last != 0) result.last_success_ns = last;
            if (!self.active_queues) return result;
            for (std::size_t index = 0; index < self.count; ++index) {
                auto* producer = self.producers[index].load(std::memory_order_acquire);
                if (!producer) continue;
                result.undrained += producer->outstanding.load(std::memory_order_relaxed);
                result.queue_high_water[index] = producer->high_water.load(std::memory_order_relaxed);
                for (std::size_t domain = 0; domain < domain_count; ++domain)
                    for (std::size_t level = 0; level < level_count; ++level)
                        result.dropped[domain][level] += producer->dropped[domain][level].load(std::memory_order_relaxed);
            }
            return result;
        }

        auto emit(this Impl& self, std::span<SinkRecord const> lines) noexcept -> void {
            if (!self.sink) return;
            if (write_batch(self.sink, lines)) {
                auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch());
                self.last_success_ns.store(now.count(), std::memory_order_relaxed);
            } else {
                self.sink_errors.fetch_add(1, std::memory_order_relaxed);
            }
        }

        auto record_ring(this Impl& self, LogSlot const& slot) -> void {
            if (!self.settings.ring_capacity || slot.level < get_ring_level()) return;
            std::lock_guard lock(self.ring_mutex);
            while (self.ring.size() >= self.settings.ring_capacity) {
                self.ring.pop_front();
                ++self.evicted;
            }
            self.ring.push_back(LogRingEntry{
                .seq = ++self.next_seq,
                .wall_epoch_ns = slot.wall_epoch_ns,
                .monotonic_ns = slot.monotonic_ns,
                .level = slot.level,
                .domain = slot.domain,
                .event_code = slot.event_code,
                .context = slot.context,
                .message = std::string(slot.message.data(), slot.message_size),
            });
        }

        auto report_drops(this Impl& self) -> void {
            auto counts = self.diagnostics().dropped;
            std::array<std::array<char, line_capacity>, domain_count> bytes;
            std::array<SinkRecord, domain_count> lines;
            std::size_t used = 0;
            for (std::size_t domain = 0; domain < domain_count; ++domain) {
                if (counts[domain] == self.reported[domain]) continue;
                LogSlot slot;
                stamp(slot);
                slot.level = Level::warn;
                slot.domain = static_cast<Domain>(domain);
                slot.event_code = dropped_event_code;
                auto out = std::format_to(slot.message.data(), "dropped");
                for (std::size_t level = 0; level < level_count; ++level) {
                    auto delta = counts[domain][level] - self.reported[domain][level];
                    if (delta != 0) out = std::format_to(out, " {}={}", name(static_cast<Level>(level)), delta);
                }
                slot.message_size = static_cast<std::uint16_t>(out - slot.message.data());
                lines[used] = {encode_line(slot, self.settings.output, bytes[used]), slot.level, slot.domain, slot.event_code, slot.context};
                ++used;
            }
            self.reported = counts;
            if (used != 0) self.emit(std::span(lines).first(used));
        }

        using QueueLimits = std::array<std::size_t, max_producers>;

        auto take_batch(this Impl& self, QueueLimits& remaining) -> bool {
            std::array<std::array<char, line_capacity>, batch_capacity> bytes;
            std::array<SinkRecord, batch_capacity> lines;
            std::array<ProducerState*, batch_capacity> owners;
            std::size_t taken = 0;
            std::size_t used = 0;
            std::size_t empty = 0;
            auto n = self.active_queues ? self.count : 0;
            while (taken < batch_capacity && empty < n) {
                auto index = self.next_producer;
                self.next_producer = (index + 1) % n;
                auto* producer = self.producers[index].load(std::memory_order_acquire);
                if (!producer || remaining[index] == 0) {
                    ++empty;
                    continue;
                }
                empty = 0;
                auto const& slot = producer->slots[producer->queue.front()];
                self.record_ring(slot);
                if (self.sink && enabled(slot.domain, slot.level)) {
                    lines[used] = {encode_line(slot, self.settings.output, bytes[used]), slot.level, slot.domain, slot.event_code, slot.context};
                    ++used;
                }
                owners[taken++] = producer;
                producer->queue.consume();
                --remaining[index];
            }
            if (taken == 0) return false;
            if (used != 0) self.emit(std::span(lines).first(used));
            for (auto* producer : std::span(owners).first(taken))
                producer->outstanding.fetch_sub(1, std::memory_order_relaxed);
            return true;
        }

        auto limits(this Impl const& self) noexcept -> QueueLimits {
            QueueLimits result{};
            if (!self.active_queues) return result;
            for (std::size_t index = 0; index < self.count; ++index)
                if (auto* producer = self.producers[index].load(std::memory_order_acquire))
                    result[index] = producer->queue.readable();
            return result;
        }

        auto settled(this Impl const& self) noexcept -> bool {
            if (!self.active_queues) return true;
            for (std::size_t index = 0; index < self.count; ++index) {
                auto* producer = self.producers[index].load(std::memory_order_acquire);
                if (!producer) continue;
                if ((producer->gate.load(std::memory_order_acquire) & active) ||
                    producer->outstanding.load(std::memory_order_relaxed) != 0) return false;
            }
            return true;
        }

        auto run(this Impl& self) -> void {
            auto next_report = Clock::now() + report_interval;
            for (;;) {
                {
                    std::unique_lock lock(self.control);
                    if (self.reopen_requested && !self.reopen_result) {
                        lock.unlock();
                        auto remaining = self.limits();
                        while (self.take_batch(remaining)) {}
                        auto result = reopen_sink(self.sink);
                        if (!result) self.sink_errors.fetch_add(1, std::memory_order_relaxed);
                        lock.lock();
                        self.reopen_result = result;
                        self.changed.notify_all();
                    }
                }
                auto remaining = self.limits();
                auto wrote = self.take_batch(remaining);
                if (self.stopping.load(std::memory_order_acquire) && self.settled()) break;
                auto now = Clock::now();
                if (now >= next_report) {
                    self.report_drops();
                    next_report = now + report_interval;
                }
                if (!wrote) self.wake.wait(next_report);
            }
            self.report_drops();
            std::lock_guard lock(self.control);
            self.finished = true;
            self.changed.notify_all();
        }

        auto stop(this Impl& self) noexcept -> void {
            {
                std::lock_guard lock(self.producer_mutex);
                self.stopping.store(true, std::memory_order_release);
                for (std::size_t index = 0; index < self.count; ++index)
                    if (auto* producer = self.producers[index].load(std::memory_order_acquire))
                        producer->gate.fetch_or(closed, std::memory_order_release);
            }
            self.wake.signal();
        }
    };

    Logger::Logger(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}

    auto Logger::start(Sink sink, std::size_t producers, Settings settings)
        -> std::expected<std::unique_ptr<Logger>, std::error_code> {
        if (producers == 0 || producers > max_producers)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        auto logger = std::unique_ptr<Logger>(new Logger(std::make_unique<Impl>(std::move(sink), producers, settings)));
        auto& impl = *logger->impl_;
        if (impl.active_queues) {
            try { impl.writer = std::thread([&impl] { impl.run(); }); }
            catch (std::system_error const& error) { return std::unexpected(error.code()); }
        }
        return logger;
    }

    Logger::~Logger() {
        if (impl_->writer.joinable()) {
            impl_->stop();
            impl_->writer.join();
        }
    }

    auto Logger::producer(this Logger const& self, std::size_t index) noexcept -> std::optional<Producer> {
        auto& impl = *self.impl_;
        if (index >= impl.count) return std::nullopt;
        if (!impl.active_queues) return Producer(nullptr, impl.settings.privacy);
        auto* state = impl.get_or_create_producer(index);
        if (!state) return std::nullopt;
        return Producer(state, impl.settings.privacy);
    }

    auto Logger::diagnostics(this Logger const& self) noexcept -> Diagnostics {
        return self.impl_->diagnostics();
    }

    auto Logger::reopen(this Logger& self) -> SinkResult {
        auto& impl = *self.impl_;
        if (!impl.active_queues) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
        std::unique_lock lock(impl.control);
        if (impl.stopping.load(std::memory_order_acquire))
            return std::unexpected(std::make_error_code(std::errc::operation_canceled));
        if (impl.reopen_requested)
            return std::unexpected(std::make_error_code(std::errc::device_or_resource_busy));
        impl.reopen_requested = true;
        impl.wake.signal();
        impl.changed.wait(lock, [&impl] { return impl.reopen_result.has_value() || impl.finished; });
        auto result = impl.reopen_result.value_or(
            std::unexpected(std::make_error_code(std::errc::operation_canceled)));
        impl.reopen_result.reset();
        impl.reopen_requested = false;
        return result;
    }

    auto Logger::drain(this Logger& self, Clock::time_point deadline) -> DrainResult {
        auto& impl = *self.impl_;
        std::unique_lock lock(impl.control);
        if (!impl.finished) impl.stop();
        auto completed = impl.changed.wait_until(lock, deadline, [&impl] { return impl.finished; });
        return {completed, impl.diagnostics()};
    }

    auto Logger::snapshot_logs(this Logger const& self, LogRingQuery const& query) -> LogRingSnapshot {
        auto const& impl = *self.impl_;
        LogRingSnapshot out{};
        std::lock_guard lock(impl.ring_mutex);
        out.latest_seq = impl.next_seq;
        out.evicted = impl.evicted;
        auto cap = std::min<std::size_t>(query.limit ? query.limit : 256, 2048);
        auto contains_ci = [](std::string_view haystack, std::string_view needle) {
            if (needle.empty()) return true;
            auto it = std::ranges::search(haystack, needle, [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
            });
            return !it.empty();
        };
        for (auto const& entry : impl.ring) {
            if (entry.seq <= query.since_seq) continue;
            if (query.min_level && entry.level < *query.min_level) continue;
            if (query.domain && entry.domain != *query.domain) continue;
            if (!query.search.empty() && !contains_ci(entry.message, query.search) &&
                !contains_ci(name(entry.domain), query.search)) continue;
            out.entries.push_back(entry);
            if (out.entries.size() >= cap) break;
        }
        return out;
    }

    auto Logger::clear_ring(this Logger& self) -> void {
        auto& impl = *self.impl_;
        std::lock_guard lock(impl.ring_mutex);
        impl.ring.clear();
    }
}
