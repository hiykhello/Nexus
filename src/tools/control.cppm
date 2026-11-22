export module cli.control;
import std;
import nexus.compat;
import state.lock;

export namespace cli {
    enum class ControlRole { administrator, reader };
    using ControlHandler=nexus::function_ref<std::expected<std::string,std::string>(
        ControlRole,std::span<std::string_view const>)>;

    struct ControlDiagnostics {
        std::uint64_t authorized=0;
        std::uint64_t unauthorized=0;
        std::uint64_t expired=0;
        std::uint64_t reply_failed=0;
    };

    class LocalControl {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        LocalControl() noexcept;
        ~LocalControl();
        LocalControl(LocalControl const&)=delete;
        auto operator=(LocalControl const&) -> LocalControl& = delete;
        auto start(std::string_view path,std::optional<std::uint32_t> reader={}) -> std::expected<void,std::string>;
        auto poll(ControlHandler handler) -> void;
        auto stop() noexcept -> void;
        [[nodiscard]] auto active() const noexcept -> bool;
        [[nodiscard]] auto instance() const noexcept -> std::string_view;
        [[nodiscard]] auto diagnostics() const noexcept -> ControlDiagnostics;
    };

    struct SelectorChoice {
        std::string group;
        std::string member;
    };

    class SelectorState {
        std::optional<::state::InstanceLock> instance_;
        std::uint64_t revision_=0;
        std::vector<SelectorChoice> choices_;
    public:
        SelectorState() noexcept=default;
        ~SelectorState();
        SelectorState(SelectorState const&)=delete;
        auto operator=(SelectorState const&) -> SelectorState& =delete;
        auto open(this SelectorState& self,std::string const& path) -> std::expected<void,std::string>;
        // False means rename succeeded but directory sync did not confirm durability.
        auto select(this SelectorState& self,std::string_view group,std::string_view member)
            -> std::expected<bool,std::string>;
        [[nodiscard]] auto choices(this SelectorState const& self) noexcept -> std::span<SelectorChoice const> {
            return self.choices_;
        }
    };

    auto run_control(int argc,char** argv) -> int;
}
