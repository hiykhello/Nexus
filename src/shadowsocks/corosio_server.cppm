module;
#if !defined(_WIN32)
#include <cerrno>
#include <sys/socket.h>
#endif
export module shadowsocks.corosio_server;
import std;
import crypto;
import shadowsocks.chunk;
import shadowsocks.header;
import shadowsocks.identity;
import shadowsocks.key;
import shadowsocks.request;
import shadowsocks.response;
import shadowsocks.replay;
import platform.wall_clock;
import capy;
import corosio;

export namespace shadowsocks::detail {
    enum class ServerReadError { invalid_input, timeout, transport, truncated, invalid_request };
    struct TcpIdentityUser {
        std::span<std::uint8_t const> key;
        ReplayTable* replay;
        IdentityBlock hash;
    };
    // Non-owning flat open-addressing hash index over TcpIdentityUser::hash for O(1), zero-alloc auth.
    class IdentityTable {
        static constexpr std::uint32_t kEmpty = 0xffffffffu;
        std::vector<std::uint32_t> buckets_;
        std::uint64_t seed_ = 0;

        static auto splitmix64(std::uint64_t x) noexcept -> std::uint64_t {
            x += 0x9e3779b97f4a7c15ULL;
            x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
            x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
            return x ^ (x >> 31);
        }
        static auto hash_id(IdentityBlock const& id, std::uint64_t seed) noexcept -> std::uint64_t {
            std::uint64_t lo = 0, hi = 0;
            std::memcpy(&lo, id.data(), 8);
            std::memcpy(&hi, id.data() + 8, 8);
            return splitmix64(lo ^ seed) ^ splitmix64(hi ^ (seed * 0x9e3779b97f4a7c15ULL + 1u));
        }
    public:
        IdentityTable() = default;
        explicit IdentityTable(std::span<TcpIdentityUser const> users) {
            if (users.empty()) return;
            seed_ = 0x517cc1b727220a95ULL;
            (void)crypto::random_bytes(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(&seed_), sizeof(seed_)));
            std::size_t cap = 4;
            while (cap < users.size() * 2) cap <<= 1;
            buckets_.assign(cap, kEmpty);
            std::size_t const mask = cap - 1;
            for (std::size_t i = 0; i < users.size(); ++i) {
                auto slot = static_cast<std::size_t>(hash_id(users[i].hash, seed_)) & mask;
                while (buckets_[slot] != kEmpty) slot = (slot + 1) & mask;
                buckets_[slot] = static_cast<std::uint32_t>(i);
            }
        }
        [[nodiscard]] auto find(std::span<TcpIdentityUser const> users, IdentityBlock const& hash) const noexcept
            -> std::optional<std::size_t> {
            if (buckets_.empty() || users.empty()) return std::nullopt;
            std::size_t const mask = buckets_.size() - 1;
            auto slot = static_cast<std::size_t>(hash_id(hash, seed_)) & mask;
            while (buckets_[slot] != kEmpty) {
                auto const idx = buckets_[slot];
                if (idx < users.size() && crypto::constant_time_equal(hash, users[idx].hash)) return idx;
                slot = (slot + 1) & mask;
            }
            return std::nullopt;
        }
        [[nodiscard]] auto empty() const noexcept -> bool { return buckets_.empty(); }
    };
    struct AcceptedRequest {
        ChunkCipher cipher;
        std::vector<std::uint8_t> salt;
        RequestHeader header;
        std::vector<std::uint8_t> unread;
        std::optional<std::size_t> user{};
    };
    // Initial read is deliberately a single operation. All failures cancel the
    // socket; caller owns it until the canceled operations have drained.
    template<class Socket>
    auto receive_request(Socket& socket, std::span<std::uint8_t const> psk, ReplayTable* replay,
                         std::chrono::steady_clock::time_point deadline,std::span<TcpIdentityUser const> users,
                         CipherMethod method=CipherMethod::aes, IdentityTable const* user_index=nullptr)
        -> capy::task<std::expected<AcceptedRequest,ServerReadError>> {
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        if (psk.size()!=16 && psk.size()!=32) co_return std::unexpected(ServerReadError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerReadError::timeout);
        std::array<std::uint8_t, 4096> initial_buf;
        auto operation=socket.read_some(capy::mutable_buffer(initial_buf.data(),initial_buf.size()));
        auto [error,n]=co_await corosio::timeout(std::move(operation),deadline);
        if (capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
            co_return std::unexpected(ServerReadError::timeout);
        if (capy::is_eof(error) || (!error && !n)) co_return std::unexpected(ServerReadError::truncated);
        if (error || n>initial_buf.size()) co_return std::unexpected(ServerReadError::transport);
        auto const input_bytes = std::span<std::uint8_t const>(initial_buf.data(), n);
        std::optional<std::size_t> user;
        if (!users.empty()) {
            if (n < psk.size()+16) co_return std::unexpected(ServerReadError::invalid_request);
            auto hash=tcp_identity(psk,input_bytes.first(psk.size()),input_bytes.subspan(psk.size()).first<16>(),false);
            if (!hash) co_return std::unexpected(ServerReadError::invalid_request);
            if (user_index && !user_index->empty()) {
                user = user_index->find(users, *hash);
            } else {
                for (std::size_t index=0;index<users.size();++index)
                    if (crypto::constant_time_equal(*hash,users[index].hash)) user=index;
            }
            if (!user) co_return std::unexpected(ServerReadError::invalid_request);
            psk=users[*user].key;
            replay=users[*user].replay;
        }
        if (!replay) co_return std::unexpected(ServerReadError::invalid_input);
        auto prefix=decode_request_prefix_current(psk,input_bytes,*replay,user.has_value(),method);
        if (!prefix) co_return std::unexpected(ServerReadError::invalid_request);
        auto const start=prefix->consumed, end=start+prefix->header_length+16;
        std::unique_ptr<std::uint8_t[]> overflow;
        std::uint8_t* storage = initial_buf.data();
        if (end > initial_buf.size()) {
            overflow = std::make_unique_for_overwrite<std::uint8_t[]>(end);
            std::memcpy(overflow.get(), initial_buf.data(), n);
            storage = overflow.get();
        }
        auto filled = n;
        while (filled < end) {
            if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerReadError::timeout);
            auto read=socket.read_some(capy::mutable_buffer(storage+filled,end-filled));
            auto [read_error,count]=co_await corosio::timeout(std::move(read),deadline);
            if (capy::is_timeout(read_error) || (!read_error && std::chrono::steady_clock::now()>=deadline))
                co_return std::unexpected(ServerReadError::timeout);
            if (capy::is_eof(read_error) || (!read_error && !count)) co_return std::unexpected(ServerReadError::truncated);
            if (read_error || count>end-filled) co_return std::unexpected(ServerReadError::transport);
            filled+=count;
        }
        auto request=decode_request_header(std::move(*prefix),std::span<std::uint8_t const>(storage+start,end-start));
        if (!request) co_return std::unexpected(ServerReadError::invalid_request);
        std::vector<std::uint8_t> unread;
        if (filled > end) unread.assign(storage + end, storage + filled);
        guard.done=true;
        co_return AcceptedRequest{std::move(request->cipher),std::move(request->salt),std::move(request->header),std::move(unread),user};
    }
    template<class Socket>
    auto receive_request(Socket& socket,std::span<std::uint8_t const> psk,ReplayTable& replay,
                         std::chrono::steady_clock::time_point deadline) {
        return receive_request(socket,psk,&replay,deadline,{});
    }
    enum class ServerWriteError { invalid_input, random, timeout, transport, partial_write };
    // First payload must be nonempty; loops partial non-blocking writes until complete or deadline.
    template<class Socket>
    auto send_response(Socket& socket,std::span<std::uint8_t const> psk,std::span<std::uint8_t const> request_salt,
                       std::span<std::uint8_t const> payload,std::chrono::steady_clock::time_point deadline,
                       CipherMethod method=CipherMethod::aes)
        -> capy::task<std::expected<ChunkCipher,ServerWriteError>> {
        if ((psk.size()!=16 && psk.size()!=32) || request_salt.size()!=psk.size() || payload.empty() || payload.size()>65535)
            co_return std::unexpected(ServerWriteError::invalid_input);
        bool const bounded = deadline != std::chrono::steady_clock::time_point::max();
        if (bounded && std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerWriteError::timeout);
        std::array<std::uint8_t, 32> salt_buf;
        auto const salt = std::span(salt_buf).first(psk.size());
        if (!crypto::random_bytes(salt)) co_return std::unexpected(ServerWriteError::random);
        auto wall=platform::calibrated_wall_seconds();
        if (wall<0) co_return std::unexpected(ServerWriteError::invalid_input);
        auto response=encode_response(psk,salt,request_salt,static_cast<std::uint64_t>(wall),payload,method);
        if (!response) co_return std::unexpected(ServerWriteError::invalid_input);
        if (bounded && std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerWriteError::timeout);
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        std::size_t offset = 0;
#if !defined(_WIN32)
        if constexpr (requires(Socket& s) { { s.native_handle() } -> std::convertible_to<int>; }) {
            if (!bounded) {
                int const fd = static_cast<int>(socket.native_handle());
                if (fd >= 0) {
#ifdef MSG_NOSIGNAL
                    constexpr int kSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
                    constexpr int kSendFlags = MSG_DONTWAIT;
#endif
                    while (offset < response->wire.size()) {
                        ssize_t const w = ::send(fd, response->wire.data() + offset, response->wire.size() - offset, kSendFlags);
                        if (w > 0) { offset += static_cast<std::size_t>(w); continue; }
                        if (w < 0 && errno == EINTR) continue;
                        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                        co_return std::unexpected(ServerWriteError::transport);
                    }
                    if (offset == response->wire.size()) {
                        guard.done = true;
                        co_return std::move(response->cipher);
                    }
                }
            }
        }
#endif
        while (offset < response->wire.size()) {
            if (bounded && std::chrono::steady_clock::now()>=deadline)
                co_return std::unexpected(ServerWriteError::timeout);
            std::error_code error;
            std::size_t n = 0;
            if (bounded) {
                auto operation=socket.write_some(capy::const_buffer(response->wire.data()+offset,response->wire.size()-offset));
                std::tie(error,n)=co_await corosio::timeout(std::move(operation),deadline);
                if (capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
                    co_return std::unexpected(ServerWriteError::timeout);
            } else {
                std::tie(error,n)=co_await socket.write_some(capy::const_buffer(response->wire.data()+offset,response->wire.size()-offset));
            }
            if (error) co_return std::unexpected(ServerWriteError::transport);
            if (!n || n>response->wire.size()-offset) co_return std::unexpected(ServerWriteError::partial_write);
            offset+=n;
        }
        guard.done=true; co_return std::move(response->cipher);
    }
}
