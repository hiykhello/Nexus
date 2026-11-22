module state.owner;
import std;

namespace state {
    struct StateOwner::Impl {
        struct Work {
            std::uint64_t revision;
            std::uint64_t epoch;
            Bytes payload;
            std::promise<std::optional<CommitState>> publication;
            std::promise<CommitResult> result;
        };

        InstanceLock instance;
        SnapshotSpec spec;
        OwnerLimits limits;
        ClearEpoch epoch;
        std::thread worker;
        std::mutex mutex;
        std::condition_variable changed;
        std::deque<Work> queue;
        std::size_t pending = 0;
        std::size_t charged = 0;
        bool stopping = false;

        Impl(InstanceLock lock, SnapshotSpec options, OwnerLimits budget, std::uint64_t initial_epoch)
            : instance(std::move(lock)), spec(std::move(options)), limits(budget), epoch(initial_epoch) {}

        auto run(this Impl& self) -> void {
            std::unique_lock lock(self.mutex);
            for (;;) {
                self.changed.wait(lock, [&] { return self.stopping || !self.queue.empty(); });
                if (self.queue.empty()) return;
                Work request = std::move(self.queue.front());
                self.queue.pop_front();
                lock.unlock();

                bool published = false;
                auto on_visible = [&]() noexcept {
                    request.publication.set_value(CommitState::visible);
                    published = true;
                };
                auto result = commit_snapshot(self.instance, self.spec, request.revision, request.epoch,
                                              request.payload, &self.epoch, OnVisible{on_visible});
                if (!published) request.publication.set_value(std::nullopt);
                auto charge = request.payload.capacity();
                Bytes{}.swap(request.payload);
                lock.lock();
                self.charged -= charge;
                --self.pending;
                request.result.set_value(std::move(result));
                self.changed.notify_all();
            }
        }

        auto stop(this Impl& self) noexcept -> void {
            self.stopping = true;
            self.changed.notify_all();
        }
    };

    StateOwner::StateOwner(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}

    StateOwner::~StateOwner() {
        {
            std::lock_guard lock(impl_->mutex);
            impl_->stop();
        }
        if (impl_->worker.joinable()) impl_->worker.join();
    }

    auto StateOwner::start(InstanceLock instance, SnapshotSpec spec, OwnerLimits limits, std::uint64_t initial_epoch)
        -> std::expected<std::unique_ptr<StateOwner>, StateError> {
        auto valid = validate_snapshot(spec);
        if (!valid) return std::unexpected(valid.error());
        if (!limits.bytes || !limits.requests || instance.directory() < 0)
            return std::unexpected(StateError{Stage::validate});
        // Workers may read one existing snapshot as scratch outside the
        // accepted request budget. Bound that scratch by the same byte limit.
        spec.envelope.max_payload = static_cast<std::uint32_t>(
            std::min<std::size_t>(spec.envelope.max_payload, limits.bytes));
        {
            auto existing = load_snapshot(instance, spec);
            if (!existing) return std::unexpected(existing.error());
            if (*existing) initial_epoch = std::max(initial_epoch, (**existing).header.clear_epoch);
        }
        auto owner = std::unique_ptr<StateOwner>(new StateOwner(
            std::make_unique<Impl>(std::move(instance), std::move(spec), limits, initial_epoch)));
        auto& impl = *owner->impl_;
        try { impl.worker = std::thread([&impl] { impl.run(); }); }
        catch (std::system_error const& error) { return std::unexpected(StateError{Stage::worker, error.code()}); }
        return owner;
    }

    auto StateOwner::submit(this StateOwner& self, std::uint64_t revision, std::uint64_t epoch, Bytes payload)
        -> std::expected<Ticket, StateError> {
        auto& impl = *self.impl_;
        std::lock_guard lock(impl.mutex);
        if (impl.stopping) return std::unexpected(StateError{Stage::stopped});
        if (epoch != impl.epoch.current()) return std::unexpected(StateError{Stage::stale_epoch});
        if (revision == 0 || payload.size() > impl.spec.envelope.max_payload)
            return std::unexpected(StateError{Stage::validate});
        auto charge = payload.capacity();
        if (impl.pending == impl.limits.requests || charge > impl.limits.bytes - impl.charged)
            return std::unexpected(StateError{Stage::capacity});
        Impl::Work work{revision, epoch, std::move(payload), {}, {}};
        auto publication = work.publication.get_future();
        auto result = work.result.get_future();
        impl.queue.push_back(std::move(work));
        impl.charged += charge;
        ++impl.pending;
        impl.changed.notify_one();
        return Ticket{CommitState::accepted, std::move(publication), std::move(result)};
    }

    auto StateOwner::current_epoch(this StateOwner const& self) noexcept -> std::uint64_t {
        return self.impl_->epoch.current();
    }

    auto StateOwner::advance_epoch(this StateOwner& self) -> std::expected<std::uint64_t, StateError> {
        return self.impl_->epoch.advance();
    }

    auto StateOwner::drain(this StateOwner& self, Clock::time_point deadline) -> DrainResult {
        auto& impl = *self.impl_;
        std::unique_lock lock(impl.mutex);
        impl.stop();
        auto completed = impl.changed.wait_until(lock, deadline, [&] { return impl.pending == 0; });
        return {completed, impl.pending, impl.charged};
    }
}
