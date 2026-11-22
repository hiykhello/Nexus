// Included beside the socket relay and shared write helper.
#pragma once
        struct PrincipalClientStream {
            Session& session;
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                auto [error,n]=co_await session.client.read_some(capy::mutable_buffer(bytes.data(),bytes.size()));
                if (error==capy::cond::eof) co_return 0;
                if (error) co_return std::unexpected(error.message());
                co_return n;
            }
            auto send(std::span<std::uint8_t const> bytes) {return write_all(session.client,bytes,session);}
            auto close_output() -> capy::task<bool> {
                co_return !session.client.shutdown(io::shutdown_send);
            }
        };
