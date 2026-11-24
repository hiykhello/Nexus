module;
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <liburing.h>
#include <sys/socket.h>
#include <time.h>

module platform.uring_buf_ring;
import std;

namespace platform {
    namespace {
        constexpr std::uint64_t kCancelTag = ~std::uint64_t{0};

        auto is_power_of_two(std::uint32_t v) noexcept -> bool {
            return v >= 4 && (v & (v - 1u)) == 0u;
        }
    }

    struct UringMultishotLoop::Impl {
        struct io_uring ring{};
        bool ring_init = false;
        struct io_uring_buf_ring* buf_ring = nullptr;
        std::uint32_t entries = 0;
        std::uint32_t buf_size = 0;
        std::uint16_t bgid = 0;
        int ring_mask = 0;
        std::vector<std::uint8_t> slab;
        std::vector<std::uint8_t> leased;
        UringMultishotStats stats{};

        ~Impl() {
            if (buf_ring && ring_init) {
                io_uring_free_buf_ring(&ring, buf_ring, entries, bgid);
                buf_ring = nullptr;
            }
            if (ring_init) {
                io_uring_queue_exit(&ring);
                ring_init = false;
            }
        }

        auto slot_ptr(std::uint16_t bid) noexcept -> std::uint8_t* {
            return slab.data() + static_cast<std::size_t>(bid) * buf_size;
        }
        auto slot_ptr(std::uint16_t bid) const noexcept -> std::uint8_t const* {
            return slab.data() + static_cast<std::size_t>(bid) * buf_size;
        }
    };

    auto UringMultishotLoop::ImplDeleter::operator()(Impl* ptr) const noexcept -> void {
        delete ptr;
    }

    UringMultishotLoop::UringMultishotLoop(std::unique_ptr<Impl, ImplDeleter> impl) noexcept
        : impl_(std::move(impl)) {}

    auto UringMultishotLoop::create(UringBufRingConfig cfg)
        -> std::expected<UringMultishotLoop, int> {
        if (!is_power_of_two(cfg.ring_entries) || cfg.ring_entries > 4096u ||
            !is_power_of_two(cfg.sq_entries) || cfg.sq_entries > 4096u ||
            cfg.buffer_size < 256u || cfg.buffer_size > 65536u) {
            return std::unexpected(EINVAL);
        }
        auto total_bytes = static_cast<std::size_t>(cfg.ring_entries) * cfg.buffer_size;
        if (total_bytes > kMaxMemoryBudget) return std::unexpected(ENOMEM);

        std::unique_ptr<Impl, ImplDeleter> impl(new (std::nothrow) Impl());
        if (!impl) return std::unexpected(ENOMEM);

        if (int rc = io_uring_queue_init(cfg.sq_entries, &impl->ring, 0); rc < 0) {
            return std::unexpected(-rc);
        }
        impl->ring_init = true;
        impl->entries = cfg.ring_entries;
        impl->buf_size = cfg.buffer_size;
        impl->bgid = cfg.buffer_group_id;
        impl->ring_mask = io_uring_buf_ring_mask(cfg.ring_entries);

        int err = 0;
        impl->buf_ring = io_uring_setup_buf_ring(&impl->ring, cfg.ring_entries, cfg.buffer_group_id, 0, &err);
        if (!impl->buf_ring) {
            return std::unexpected(err < 0 ? -err : (err > 0 ? err : ENOSYS));
        }

        impl->slab.resize(total_bytes);
        impl->leased.assign(cfg.ring_entries, 0u);
        for (std::uint32_t i = 0; i < cfg.ring_entries; ++i) {
            io_uring_buf_ring_add(
                impl->buf_ring,
                impl->slot_ptr(static_cast<std::uint16_t>(i)),
                cfg.buffer_size,
                static_cast<std::uint16_t>(i),
                impl->ring_mask,
                static_cast<int>(i));
        }
        io_uring_buf_ring_advance(impl->buf_ring, static_cast<int>(cfg.ring_entries));
        return UringMultishotLoop(std::move(impl));
    }

    auto UringMultishotLoop::arm_recv_multishot(int fd, std::uint64_t tag) noexcept
        -> std::expected<void, int> {
        if (!impl_ || fd < 0 || tag == kCancelTag) return std::unexpected(EINVAL);
        struct io_uring_sqe* sqe = io_uring_get_sqe(&impl_->ring);
        if (!sqe) {
            if (int rc = io_uring_submit(&impl_->ring); rc < 0) return std::unexpected(-rc);
            sqe = io_uring_get_sqe(&impl_->ring);
            if (!sqe) return std::unexpected(EAGAIN);
        }
        io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
        sqe->flags |= IOSQE_BUFFER_SELECT;
        sqe->buf_group = impl_->bgid;
        io_uring_sqe_set_data64(sqe, tag);
        ++impl_->stats.rearms;
        return {};
    }

    auto UringMultishotLoop::arm_read_multishot(int fd, std::uint64_t tag) noexcept
        -> std::expected<void, int> {
        if (!impl_ || fd < 0 || tag == kCancelTag) return std::unexpected(EINVAL);
        struct io_uring_sqe* sqe = io_uring_get_sqe(&impl_->ring);
        if (!sqe) {
            if (int rc = io_uring_submit(&impl_->ring); rc < 0) return std::unexpected(-rc);
            sqe = io_uring_get_sqe(&impl_->ring);
            if (!sqe) return std::unexpected(EAGAIN);
        }
        io_uring_prep_read_multishot(sqe, fd, 0, 0, impl_->bgid);
        sqe->buf_group = impl_->bgid;
        io_uring_sqe_set_data64(sqe, tag);
        ++impl_->stats.rearms;
        return {};
    }

    auto UringMultishotLoop::submit() noexcept -> std::expected<void, int> {
        if (!impl_ || !impl_->ring_init) return std::unexpected(EINVAL);
        if (int rc = io_uring_submit(&impl_->ring); rc < 0) return std::unexpected(-rc);
        return {};
    }

    auto UringMultishotLoop::cancel_fd(int fd) noexcept -> std::expected<void, int> {
        if (!impl_ || fd < 0) return std::unexpected(EINVAL);
        struct io_uring_sqe* sqe = io_uring_get_sqe(&impl_->ring);
        if (!sqe) {
            if (int rc = io_uring_submit(&impl_->ring); rc < 0) return std::unexpected(-rc);
            sqe = io_uring_get_sqe(&impl_->ring);
            if (!sqe) return std::unexpected(EAGAIN);
        }
        io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
        io_uring_sqe_set_data64(sqe, kCancelTag);
        if (int rc = io_uring_submit(&impl_->ring); rc < 0) return std::unexpected(-rc);
        return {};
    }

    auto UringMultishotLoop::poll_events(std::span<MultishotEvent> out,
                                         std::uint32_t wait_nr,
                                         std::uint32_t timeout_ms) noexcept
        -> std::expected<std::size_t, int> {
        if (!impl_) return std::unexpected(EINVAL);
        if (out.empty()) return std::size_t{0};

        struct io_uring_cqe* cqe = nullptr;
        if (wait_nr > 0) {
            struct __kernel_timespec ts{};
            ts.tv_sec = static_cast<long long>(timeout_ms / 1000u);
            ts.tv_nsec = static_cast<long long>(timeout_ms % 1000u) * 1000000LL;
            int rc = io_uring_submit_and_wait_timeout(&impl_->ring, &cqe, wait_nr, &ts, nullptr);
            if (rc < 0 && rc != -ETIME && rc != -EINTR) return std::unexpected(-rc);
        } else {
            int rc = io_uring_submit(&impl_->ring);
            if (rc < 0) return std::unexpected(-rc);
        }

        std::size_t count = 0;
        unsigned head = 0;
        unsigned seen = 0;
        io_uring_for_each_cqe(&impl_->ring, head, cqe) {
            if (count == out.size()) break;
            ++seen;
            auto tag = io_uring_cqe_get_data64(cqe);
            if (tag == kCancelTag) continue;

            MultishotEvent ev{};
            ev.tag = tag;
            ev.result = cqe->res;
            ev.more_coming = (cqe->flags & IORING_CQE_F_MORE) != 0u;
            ev.has_buffer = (cqe->flags & IORING_CQE_F_BUFFER) != 0u;
            if (ev.has_buffer) {
                ev.buffer_id = static_cast<std::uint16_t>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
                if (ev.buffer_id < impl_->entries && !impl_->leased[ev.buffer_id]) {
                    impl_->leased[ev.buffer_id] = 1u;
                    ++impl_->stats.buffers_leased;
                }
            }
            ++impl_->stats.cqes_total;
            if (ev.more_coming) ++impl_->stats.multishot_hits;
            if (ev.result == -ENOBUFS) ++impl_->stats.enobufs_count;
            if (ev.result > 0) impl_->stats.bytes_received += static_cast<std::uint64_t>(ev.result);
            ev.needs_rearm = !ev.more_coming && ev.result != 0 && ev.result != -ECANCELED;
            out[count++] = ev;
        }
        if (seen > 0) io_uring_cq_advance(&impl_->ring, seen);
        return count;
    }

    auto UringMultishotLoop::buffer_view(std::uint16_t bid, std::size_t len) const noexcept
        -> std::span<std::uint8_t const> {
        if (!impl_ || bid >= impl_->entries || !impl_->leased[bid]) return {};
        auto clamped = std::min(len, static_cast<std::size_t>(impl_->buf_size));
        return {impl_->slot_ptr(bid), clamped};
    }

    auto UringMultishotLoop::recycle(std::uint16_t bid) noexcept -> bool {
        if (!impl_ || bid >= impl_->entries || !impl_->leased[bid]) return false;
        impl_->leased[bid] = 0u;
        --impl_->stats.buffers_leased;
        io_uring_buf_ring_add(
            impl_->buf_ring,
            impl_->slot_ptr(bid),
            impl_->buf_size,
            bid,
            impl_->ring_mask,
            0);
        io_uring_buf_ring_advance(impl_->buf_ring, 1);
        return true;
    }

    auto UringMultishotLoop::ring_fd() const noexcept -> int {
        return (impl_ && impl_->ring_init) ? impl_->ring.ring_fd : -1;
    }
    auto UringMultishotLoop::ring_entries() const noexcept -> std::uint32_t {
        return impl_ ? impl_->entries : 0u;
    }
    auto UringMultishotLoop::buffer_size() const noexcept -> std::uint32_t {
        return impl_ ? impl_->buf_size : 0u;
    }
    auto UringMultishotLoop::leased_count() const noexcept -> std::uint32_t {
        return impl_ ? impl_->stats.buffers_leased : 0u;
    }
    auto UringMultishotLoop::stats() const noexcept -> UringMultishotStats {
        return impl_ ? impl_->stats : UringMultishotStats{};
    }
}
