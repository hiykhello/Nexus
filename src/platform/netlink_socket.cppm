export module platform.netlink_socket;
import std;
import platform.netlink_abi;
import platform.netlink_codec;

export namespace platform::netlink {
    using Clock = std::chrono::steady_clock;
    enum class ReceiveFault { none, lost_ack, overflow, truncated, wrong_sequence, wrong_sender, malformed };
    struct NoHooks {
        static auto before_send(std::span<std::uint8_t const>, bool) noexcept -> std::error_code { return {}; }
        static auto after_receive(std::span<std::uint8_t>, bool) noexcept -> ReceiveFault { return ReceiveFault::none; }
    };
    // One private NETLINK_ROUTE socket. No subscription or shared receiver.
    // Synchronous lifecycle waits are bounded by the supplied absolute deadline.
    template <class Hooks = NoHooks> class Socket {
      public:
        static constexpr bool cancellable=requires { Hooks::cancelled(); };
      private:
        int fd_ = -1;
        std::uint32_t pid_ = 0, sequence_ = 0;
        bool pending_ = false;
        struct Cancellation { bool disabled=false; };
        struct NoCancellation {};
        [[no_unique_address]] std::conditional_t<cancellable,Cancellation,NoCancellation> cancellation_;
        std::array<std::uint8_t, 65536> input_{};
        auto error() const noexcept -> std::error_code { return {*abi::__errno_location(), std::generic_category()}; }
        auto wait(short events, Clock::time_point deadline) noexcept -> std::expected<void, Failure> {
            for (;;) {
                if constexpr(cancellable) { static_assert(noexcept(Hooks::cancelled())); if (!cancellation_.disabled && Hooks::cancelled()) return fail(Error::canceled); }
                auto now = Clock::now();
                if (now >= deadline) return fail(Error::timeout);
                auto delay = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
                abi::pollfd descriptor{fd_, events, 0};
                int count = abi::poll(&descriptor, 1, static_cast<int>(std::min<std::int64_t>(delay, std::numeric_limits<int>::max())));
                if (count < 0) {
                    auto failure = error();
                    if (failure == std::errc::interrupted) continue;
                    return fail(Error::system, failure);
                }
                if (!count) return fail(Error::timeout);
                if (descriptor.revents & (abi::POLLNVAL | abi::POLLHUP | abi::POLLERR)) return fail(Error::system, std::make_error_code(std::errc::io_error));
                if (descriptor.revents & events) return {};
            }
        }

      public:
        Socket() = default;
        Socket(Socket const &) = delete;
        auto operator=(Socket const &) -> Socket & = delete;
        Socket(Socket &&) = delete;
        auto operator=(Socket &&) -> Socket & = delete;
        ~Socket() { close(); }
        auto close() noexcept -> void {
            if (fd_ >= 0) {
                abi::close(fd_);
                fd_ = -1;
            }
            pending_ = false;
        }
        [[nodiscard]] auto native_handle() const noexcept -> int { return fd_; }
        [[nodiscard]] auto port_id() const noexcept -> std::uint32_t { return pid_; }
        [[nodiscard]] auto sequence() const noexcept -> std::uint32_t { return sequence_; }
        // Terminal rollback ignores a stop request while respecting its own
        // caller-supplied absolute deadline. Empty NoHooks has no extra state.
        auto disable_cancellation() noexcept -> void { if constexpr(cancellable) cancellation_.disabled=true; }
        [[nodiscard]] auto exchange_cancellation_disabled(bool disabled) noexcept -> bool {
            if constexpr(cancellable)return std::exchange(cancellation_.disabled,disabled);else return false;
        }
        [[nodiscard]] auto open() noexcept -> std::expected<void, Failure> {
            if (fd_ >= 0) return fail(Error::configuration);
            fd_ = abi::socket(abi::AF_NETLINK, abi::SOCK_RAW | abi::SOCK_NONBLOCK | abi::SOCK_CLOEXEC, abi::NETLINK_ROUTE);
            if (fd_ < 0) return fail(Error::system, error());
            abi::sockaddr_nl local{.nl_family = abi::AF_NETLINK};
            if (abi::bind(fd_, reinterpret_cast<abi::sockaddr const *>(&local), sizeof(local)) < 0) {
                auto failure = error();
                close();
                return fail(Error::system, failure);
            }
            unsigned int size = sizeof(local);
            if (abi::getsockname(fd_, reinterpret_cast<abi::sockaddr *>(&local), &size) < 0) {
                auto failure = error();
                close();
                return fail(Error::system, failure);
            }
            if (size != sizeof(local) || local.nl_family != abi::AF_NETLINK || local.nl_groups || !local.nl_pid) {
                close();
                return fail(Error::protocol);
            }
            pid_ = local.nl_pid;
            return {};
        }
        template <class Visitor> [[nodiscard]] auto exchange(Request request, bool dump, Clock::time_point deadline, Visitor &&visitor,bool lookup=false) -> std::expected<void, Failure> {
            if (fd_ < 0) return fail(Error::closed);
            if (!request.valid()) return fail(Error::configuration);
            if (sequence_ == std::numeric_limits<std::uint32_t>::max()) return fail(Error::sequence_exhausted);
            if constexpr(cancellable) { static_assert(noexcept(Hooks::cancelled())); if (!cancellation_.disabled && Hooks::cancelled()) return fail(Error::canceled); }
            if (Clock::now()>=deadline) return fail(Error::timeout);
            // A failed multipart receive can leave a dump active in the kernel.
            // A fresh private socket avoids EBUSY and stale partial readback;
            // the original transaction error and deadline remain unchanged.
            if (pending_) {
                close(); auto opened=open();
                if (!opened) return opened;
            }
            bool mutation = !dump && !lookup;
            request.stamp(++sequence_, pid_);
            static_assert(noexcept(Hooks::before_send(request.bytes(), mutation)));
            if (auto failure = Hooks::before_send(request.bytes(), mutation)) return fail(Error::system, failure);
            abi::sockaddr_nl kernel{.nl_family = abi::AF_NETLINK};
            for (;;) {
                if constexpr(cancellable) { if (!cancellation_.disabled && Hooks::cancelled()) return fail(Error::canceled); }
                if (Clock::now() >= deadline) return fail(Error::timeout);
                auto count = abi::sendto(fd_, request.bytes().data(), request.bytes().size(), 0, reinterpret_cast<abi::sockaddr const *>(&kernel), sizeof(kernel));
                if (count == static_cast<std::ptrdiff_t>(request.bytes().size())) { pending_=true; break; }
                if (count >= 0) { pending_=true; return fail(Error::uncertain, {}, mutation); }
                auto failure = error();
                if (failure == std::errc::interrupted) continue;
                if (failure != std::errc::resource_unavailable_try_again && failure != std::errc::operation_would_block) return fail(Error::system, failure);
                auto ready = wait(abi::POLLOUT, deadline);
                if (!ready) return ready;
            }
            ReplyState state{request.header(), dump,lookup};
            auto receive_deadline = std::min(deadline, Clock::now() + std::chrono::milliseconds(250));
            std::size_t datagrams = 0;
            while (!state.done) {
                if constexpr(cancellable) { if (!cancellation_.disabled && Hooks::cancelled()) return fail(Error::canceled,{},mutation); }
                if (Clock::now()>=receive_deadline) return fail(Error::timeout, {}, mutation);
                if (++datagrams > 4096) return fail(Error::limit, {}, mutation);
                abi::sockaddr_nl source{};
                unsigned int size = sizeof(source);
                auto count = abi::recvfrom(fd_, input_.data(), input_.size(), abi::MSG_TRUNC, reinterpret_cast<abi::sockaddr *>(&source), &size);
                if (count < 0) {
                    auto failure = error();
                    if (failure == std::errc::interrupted) continue;
                    if (failure == std::errc::resource_unavailable_try_again || failure == std::errc::operation_would_block) {
                        auto ready = wait(abi::POLLIN, receive_deadline);
                        if (!ready) {
                            auto problem = ready.error();
                            problem.may_have_changed = mutation;
                            return std::unexpected(problem);
                        }
                        continue;
                    }
                    return fail(Error::system, failure, mutation);
                }
                if (!count || static_cast<std::size_t>(count) > input_.size()) return fail(Error::protocol, {}, mutation);
                auto bytes = std::span(input_).first(static_cast<std::size_t>(count));
                static_assert(noexcept(Hooks::after_receive(bytes, mutation)));
                auto fault = Hooks::after_receive(bytes, mutation);
                if (fault == ReceiveFault::lost_ack) continue; // Consume the real ACK; the original bounded receive wait expires.
                if (fault == ReceiveFault::overflow) return fail(Error::system, std::make_error_code(std::errc::no_buffer_space), mutation);
                if (fault == ReceiveFault::truncated) return fail(Error::protocol, {}, mutation);
                if (fault == ReceiveFault::wrong_sender) source.nl_pid = 1;
                if (fault == ReceiveFault::wrong_sequence && bytes.size() >= sizeof(abi::nlmsghdr)) {
                    auto header = *native<abi::nlmsghdr>(bytes);
                    ++header.nlmsg_seq;
                    std::memcpy(bytes.data(), &header, sizeof(header));
                }
                if (fault == ReceiveFault::malformed && bytes.size() >= sizeof(abi::nlmsghdr)) {
                    auto header = *native<abi::nlmsghdr>(bytes);
                    header.nlmsg_len = 1;
                    std::memcpy(bytes.data(), &header, sizeof(header));
                }
                if (size != sizeof(source) || source.nl_family != abi::AF_NETLINK || source.nl_pid || source.nl_groups) return fail(Error::protocol, {}, mutation);
                auto result = messages(bytes, [&](Message message) { return state.receive(message, pid_, visitor); });
                if (!result) {
                    auto failure = result.error();
                    if (failure.rejected) pending_=false;
                    failure.may_have_changed = mutation;
                    return std::unexpected(failure);
                }
            }
            pending_=false;
            return {};
        }
        // Borrow only between synchronous exchanges; subsequent receives invalidate all views.
        [[nodiscard]] auto receive_buffer() noexcept -> std::span<std::uint8_t> {return input_;}
        [[nodiscard]] auto acknowledge(Request request, Clock::time_point deadline) -> std::expected<void, Failure> {
            return exchange(std::move(request), false, deadline, [](Message) -> std::expected<void,Failure> { return fail(Error::protocol); });
        }
        template<class Visitor> [[nodiscard]] auto query(Request request,Clock::time_point deadline,Visitor&& visitor) -> std::expected<void,Failure> {
            return exchange(std::move(request),false,deadline,std::forward<Visitor>(visitor),true);
        }
        template <class Visitor> [[nodiscard]] auto dump(std::uint16_t type, std::uint8_t family, Clock::time_point deadline, Visitor &&visitor) -> std::expected<void, Failure> {
            std::uint16_t flags = abi::NLM_F_REQUEST | abi::NLM_F_DUMP;
            if (type == abi::RTM_GETLINK) return exchange(Request(type, flags, abi::ifinfomsg{.ifi_family = family}), true, deadline, std::forward<Visitor>(visitor));
            if (type == abi::RTM_GETADDR) return exchange(Request(type, flags, abi::ifaddrmsg{.ifa_family = family}), true, deadline, std::forward<Visitor>(visitor));
            if (type == abi::RTM_GETNETCONF) return exchange(Request(type,flags,abi::netconfmsg{.ncm_family=family}),true,deadline,std::forward<Visitor>(visitor));
            if (type == abi::RTM_GETRULE) return exchange(Request(type,flags,abi::fib_rule_hdr{.family=family}),true,deadline,std::forward<Visitor>(visitor));
            if (type == abi::RTM_GETNEIGH) return exchange(Request(type,flags,abi::ndmsg{.family=family}),true,deadline,std::forward<Visitor>(visitor));
            if (type == abi::RTM_GETROUTE) return exchange(Request(type, flags, abi::rtmsg{.rtm_family = family}), true, deadline, std::forward<Visitor>(visitor));
            return fail(Error::configuration);
        }
    };
} // namespace platform::netlink
