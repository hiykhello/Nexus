export module desktop.ipc_client;

import std;

export namespace desktop {
    struct IpcReply {
        bool ok = false;
        std::string body;
    };

    // Builds a NEXUS/1 NUL-delimited control request frame matching src/tools/control.cpp.
    [[nodiscard]] auto build_nexus1_frame(std::span<std::string_view const> tokens)
        -> std::optional<std::string> {
        if (tokens.empty()) return std::nullopt;
        std::string wire = "NEXUS/1 ";
        for (std::size_t i = 0; i < tokens.size(); ++i) {
            if (tokens[i].empty() || tokens[i].contains('\0')) return std::nullopt;
            if (i > 0) wire.push_back('\0');
            wire.append(tokens[i]);
        }
        if (wire.size() > 1024) return std::nullopt;
        return wire;
    }

    class IpcClient {
        std::string endpoint_;
        std::chrono::milliseconds timeout_{2000};
    public:
        explicit IpcClient(std::string endpoint) : endpoint_(std::move(endpoint)) {}

        [[nodiscard]] auto endpoint(this IpcClient const& self) noexcept -> std::string_view {
            return self.endpoint_;
        }
        auto set_endpoint(this IpcClient& self, std::string endpoint) -> void {
            self.endpoint_ = std::move(endpoint);
        }

        [[nodiscard]] auto request(this IpcClient const& self, std::span<std::string_view const> tokens)
            -> IpcReply;

        [[nodiscard]] auto status(this IpcClient const& self) -> IpcReply {
            std::string_view args[] = {"status"};
            return self.request(args);
        }

        [[nodiscard]] auto reload(this IpcClient const& self) -> IpcReply {
            std::string_view args[] = {"reload"};
            return self.request(args);
        }

        [[nodiscard]] auto set_log_level(this IpcClient const& self, std::string_view level) -> IpcReply {
            std::string_view args[] = {"log-level", level};
            return self.request(args);
        }

        [[nodiscard]] auto select_outbound(
            this IpcClient const& self,
            std::string_view group,
            std::string_view member) -> IpcReply {
            std::string_view args[] = {"select", group, member};
            return self.request(args);
        }
    };
}
