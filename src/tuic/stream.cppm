export module tuic.stream;
import std;
import tuic.application;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace tuic {
    template<class App, class Driver>
    class TcpStream {
        App& app_;
        Driver& driver_;
        StreamHandle handle_;
        nex::capy::async_mutex write_lock_;
        bool canceled_ = false;
    public:
        TcpStream(App& app, Driver& driver, StreamHandle handle) noexcept
            : app_(app), driver_(driver), handle_(handle) {}
        ~TcpStream() { app_.release_stream(handle_); driver_.notify(); }
        TcpStream(TcpStream const&) = delete;
        auto operator=(TcpStream const&) -> TcpStream& = delete;

        auto cancel() noexcept -> void { canceled_ = true; driver_.notify(); }

        auto send(std::span<std::uint8_t const> data) -> nex::capy::task<bool> {
            auto [ec, guard] = co_await write_lock_.scoped_lock();
            if (ec || canceled_) co_return false;
            std::size_t off = 0;
            while (off < data.size()) {
                if (canceled_ || app_.stopping() || !driver_.running()) co_return false;
                auto chunk = std::min<std::size_t>(data.size() - off, 16384);
                if (app_.writable(handle_, chunk) && app_.send_stream(handle_, data.subspan(off, chunk))) {
                    off += chunk;
                    continue;
                }
                driver_.changed().clear();
                auto [werr] = co_await nex::corosio::timeout(driver_.changed().wait(), std::chrono::steady_clock::now() + std::chrono::seconds(300));
                if (werr) co_return false;
            }
            co_return true;
        }

        auto read(std::span<std::uint8_t> out) -> nex::capy::task<std::expected<std::size_t, std::string>> {
            for (;;) {
                if (canceled_) co_return std::unexpected("TUIC stream canceled");
                auto n = app_.read_stream(handle_, out);
                if (!n) co_return std::unexpected("TUIC stream reset");
                if (*n > 0) { driver_.notify(); co_return *n; }
                if (app_.stream_eof(handle_)) co_return std::size_t{0};
                if (app_.stream_failed(handle_) || app_.stopping() || !driver_.running())
                    co_return std::unexpected("TUIC stream closed");
                driver_.changed().clear();
                auto [werr] = co_await nex::corosio::timeout(driver_.changed().wait(), std::chrono::steady_clock::now() + std::chrono::seconds(300));
                if (werr) co_return std::unexpected("TUIC stream read timeout");
            }
        }

        auto close_output() -> nex::capy::task<bool> {
            auto [ec, guard] = co_await write_lock_.scoped_lock();
            if (ec || canceled_) co_return false;
            co_return app_.close_stream_write(handle_);
        }
    };
}
