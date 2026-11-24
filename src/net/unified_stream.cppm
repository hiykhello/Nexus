module;
#include <proxy/proxy_macros.h>

export module net.unified_stream;
import std;
import proxy.v4;
import net.tcp_fast_open_stream;
import capy;
import corosio;

export namespace net {
    PRO_DEF_MEM_DISPATCH(LowerStreamRead, read);
    PRO_DEF_MEM_DISPATCH(LowerStreamSend, send);
    PRO_DEF_MEM_DISPATCH(LowerStreamCloseOutput, close_output);
    PRO_DEF_MEM_DISPATCH(LowerStreamCancel, cancel);

    struct LowerStreamFacade : pro::facade_builder
        ::add_convention<LowerStreamRead, capy::task<std::expected<std::size_t, std::string>>(std::span<std::uint8_t>)>
        ::add_convention<LowerStreamSend, capy::task<bool>(std::span<std::uint8_t const>)>
        ::add_convention<LowerStreamCloseOutput, capy::task<bool>()>
        ::add_convention<LowerStreamCancel, void() noexcept>
        ::build {};

    // Non-owning unified stream interface for direct TCP, TFO, and detour tunnels.
    // Preserves native_handle() only on physical TCP sockets so Linux kTLS remains intact.
    class UnifiedStreamSocket {
        enum class Kind : std::uint8_t { none, tcp, fast_open, lower };
        using TcpReadOp = decltype(std::declval<corosio::tcp_socket&>().read_some(capy::mutable_buffer{}));
        using TcpWriteOp = decltype(std::declval<corosio::tcp_socket&>().write_some(capy::const_buffer{}));
        using TcpWaitOp = decltype(std::declval<corosio::tcp_socket&>().wait(corosio::wait_type::read));

        struct WaitOp {
            using Immediate = capy::results<>;
            std::variant<Immediate, TcpWaitOp> state_;

            explicit WaitOp(Immediate res) noexcept : state_(res) {}
            explicit WaitOp(TcpWaitOp&& op) noexcept(std::is_nothrow_move_constructible_v<TcpWaitOp>)
                : state_(std::in_place_index<1>, std::move(op)) {}

            [[nodiscard]] auto await_ready() const noexcept -> bool {
                if (state_.index() == 0) return true;
                return std::get<1>(state_).await_ready();
            }
            auto await_suspend(std::coroutine_handle<> h, capy::await_context const* env) -> std::coroutine_handle<> {
                if (state_.index() == 1) return std::get<1>(state_).await_suspend(h, env);
                return h;
            }
            [[nodiscard]] auto await_resume() -> Immediate {
                if (state_.index() == 0) return std::get<0>(state_);
                return std::get<1>(state_).await_resume();
            }
        };

        template<class TcpOp>
        struct StreamOp {
            using Immediate = capy::results<std::size_t>;
            using Fallback = capy::task<Immediate>;
            std::variant<Immediate, TcpOp, Fallback> state_;

            explicit StreamOp(Immediate res) noexcept : state_(res) {}
            explicit StreamOp(TcpOp&& op) noexcept(std::is_nothrow_move_constructible_v<TcpOp>)
                : state_(std::in_place_index<1>, std::move(op)) {}
            explicit StreamOp(Fallback&& task) noexcept : state_(std::in_place_index<2>, std::move(task)) {}

            [[nodiscard]] auto await_ready() const noexcept -> bool {
                if (state_.index() == 0) return true;
                if (state_.index() == 1) return std::get<1>(state_).await_ready();
                return std::get<2>(state_).await_ready();
            }
            auto await_suspend(std::coroutine_handle<> h, capy::await_context const* env) -> std::coroutine_handle<> {
                if (state_.index() == 1) return std::get<1>(state_).await_suspend(h, env);
                if (state_.index() == 2) return std::get<2>(state_).await_suspend(h, env);
                return h;
            }
            [[nodiscard]] auto await_resume() -> Immediate {
                if (state_.index() == 0) return std::get<0>(state_);
                if (state_.index() == 1) return std::get<1>(state_).await_resume();
                return std::get<2>(state_).await_resume();
            }
        };

        Kind kind_ = Kind::none;
        corosio::tcp_socket* tcp_ = nullptr;
        FastOpenStream* fast_ = nullptr;
        pro::proxy_view<LowerStreamFacade> lower_;

        static auto map_failure(bool stop_requested) noexcept -> std::error_code {
            return std::make_error_code(stop_requested ? std::errc::operation_canceled : std::errc::io_error);
        }

        auto read_fallback(capy::mutable_buffer buf) -> capy::task<capy::results<std::size_t>> {
            if (kind_ == Kind::fast_open && fast_) {
                auto stop = co_await capy::this_coro::stop_token;
                auto r = co_await fast_->read({static_cast<std::uint8_t*>(buf.data()), buf.size()});
                if (!r) co_return capy::results<std::size_t>{r.error() ? r.error() : map_failure(stop.stop_requested()), 0};
                if (*r > buf.size()) co_return capy::results<std::size_t>{std::make_error_code(std::errc::protocol_error), 0};
                co_return capy::results<std::size_t>{std::error_code{}, *r};
            }
            if (kind_ == Kind::lower && lower_) {
                auto stop = co_await capy::this_coro::stop_token;
                auto r = co_await lower_->read({static_cast<std::uint8_t*>(buf.data()), buf.size()});
                if (!r) co_return capy::results<std::size_t>{map_failure(stop.stop_requested()), 0};
                if (*r > buf.size()) co_return capy::results<std::size_t>{std::make_error_code(std::errc::protocol_error), 0};
                co_return capy::results<std::size_t>{std::error_code{}, *r};
            }
            co_return capy::results<std::size_t>{std::make_error_code(std::errc::not_connected), 0};
        }

        auto write_fallback(capy::const_buffer buf) -> capy::task<capy::results<std::size_t>> {
            if (kind_ == Kind::fast_open && fast_) {
                auto stop = co_await capy::this_coro::stop_token;
                if (!co_await fast_->send({static_cast<std::uint8_t const*>(buf.data()), buf.size()}))
                    co_return capy::results<std::size_t>{map_failure(stop.stop_requested()), 0};
                co_return capy::results<std::size_t>{std::error_code{}, buf.size()};
            }
            if (kind_ == Kind::lower && lower_) {
                auto stop = co_await capy::this_coro::stop_token;
                if (!co_await lower_->send({static_cast<std::uint8_t const*>(buf.data()), buf.size()}))
                    co_return capy::results<std::size_t>{map_failure(stop.stop_requested()), 0};
                co_return capy::results<std::size_t>{std::error_code{}, buf.size()};
            }
            co_return capy::results<std::size_t>{std::make_error_code(std::errc::not_connected), 0};
        }

    public:
        UnifiedStreamSocket() noexcept = default;
        UnifiedStreamSocket(UnifiedStreamSocket const&) = delete;
        auto operator=(UnifiedStreamSocket const&) -> UnifiedStreamSocket& = delete;

        auto bind(corosio::tcp_socket& socket) noexcept -> void {
            kind_ = Kind::tcp; tcp_ = &socket; fast_ = nullptr; lower_ = {};
        }
        auto bind(FastOpenStream& stream) noexcept -> void {
            kind_ = Kind::fast_open; tcp_ = nullptr; fast_ = &stream; lower_ = {};
        }
        template<class Lower>
        auto bind(Lower& lower) noexcept -> void {
            kind_ = Kind::lower; tcp_ = nullptr; fast_ = nullptr;
            lower_ = pro::make_proxy_view<LowerStreamFacade>(lower);
        }
        auto reset() noexcept -> void {
            kind_ = Kind::none; tcp_ = nullptr; fast_ = nullptr; lower_ = {};
        }

        [[nodiscard]] auto is_physical() const noexcept -> bool { return kind_ == Kind::tcp; }
        [[nodiscard]] auto native_handle() const noexcept -> int {
            return kind_ == Kind::tcp && tcp_ ? static_cast<int>(tcp_->native_handle()) : -1;
        }
        auto wait(corosio::wait_type what) -> WaitOp {
            if (kind_ == Kind::tcp && tcp_) return WaitOp{tcp_->wait(what)};
            return WaitOp{capy::results<>{std::make_error_code(std::errc::operation_not_supported)}};
        }
        auto cancel() noexcept -> void {
            if (kind_ == Kind::tcp && tcp_) tcp_->cancel();
            else if (kind_ == Kind::fast_open && fast_) fast_->cancel();
            else if (kind_ == Kind::lower && lower_) lower_->cancel();
        }
        auto shutdown(decltype(corosio::shutdown_send) what) noexcept -> std::error_code {
            if (kind_ == Kind::tcp && tcp_) return tcp_->shutdown(what);
            return std::make_error_code(std::errc::not_connected);
        }
        auto read_some(capy::mutable_buffer buf) -> StreamOp<TcpReadOp> {
            if (!buf.size()) return StreamOp<TcpReadOp>{capy::results<std::size_t>{std::error_code{}, 0}};
            if (kind_ == Kind::tcp && tcp_) return StreamOp<TcpReadOp>{tcp_->read_some(buf)};
            if (kind_ == Kind::none) return StreamOp<TcpReadOp>{capy::results<std::size_t>{std::make_error_code(std::errc::not_connected), 0}};
            return StreamOp<TcpReadOp>{read_fallback(buf)};
        }
        auto write_some(capy::const_buffer buf) -> StreamOp<TcpWriteOp> {
            if (!buf.size()) return StreamOp<TcpWriteOp>{capy::results<std::size_t>{std::error_code{}, 0}};
            if (kind_ == Kind::tcp && tcp_) return StreamOp<TcpWriteOp>{tcp_->write_some(buf)};
            if (kind_ == Kind::none) return StreamOp<TcpWriteOp>{capy::results<std::size_t>{std::make_error_code(std::errc::not_connected), 0}};
            return StreamOp<TcpWriteOp>{write_fallback(buf)};
        }
        auto close_output_some() -> capy::task<capy::results<std::size_t>> {
            if (kind_ == Kind::tcp && tcp_) co_return capy::results<std::size_t>{tcp_->shutdown(corosio::shutdown_send), 0};
            if (kind_ == Kind::fast_open && fast_) {
                auto stop = co_await capy::this_coro::stop_token;
                if (!co_await fast_->close_output())
                    co_return capy::results<std::size_t>{map_failure(stop.stop_requested()), 0};
                co_return capy::results<std::size_t>{std::error_code{}, 0};
            }
            if (kind_ == Kind::lower && lower_) {
                auto stop = co_await capy::this_coro::stop_token;
                if (!co_await lower_->close_output())
                    co_return capy::results<std::size_t>{map_failure(stop.stop_requested()), 0};
                co_return capy::results<std::size_t>{std::error_code{}, 0};
            }
            co_return capy::results<std::size_t>{std::make_error_code(std::errc::not_connected), 0};
        }
    };
}
