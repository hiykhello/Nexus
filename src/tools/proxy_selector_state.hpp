// Connect persisted manual choices to validated route configuration.
#pragma once
namespace cli::run_detail {
    auto overlay_selector_state(config::Config& candidate,std::span<SelectorChoice const> choices)
        -> std::expected<void,std::string> {
        for (auto const& choice:choices) {
            auto group=std::ranges::find(candidate.selectors,choice.group,&config::OutboundSelector::name);
            if (group==candidate.selectors.end() || group->mode!=config::OutboundGroupMode::select ||
                std::ranges::find(group->members,choice.member)==group->members.end())
                return std::unexpected("selector state does not match a configured manual group and member");
            group->selected=choice.member;
        }
        return {};
    }

    auto initialize_selector_state(SelectorState& state,config::Config& config)
        -> std::expected<void,std::string> {
        if (config.selector_state_directory.empty()) return {};
        auto opened=state.open(config.selector_state_directory);
        if (!opened || state.choices().empty()) return opened;
        auto requested=config;
        auto restored=overlay_selector_state(requested,state.choices());
        if (!restored) return restored;
        auto next=config::reselect_outbounds(config,requested);
        if (!next) return std::unexpected("selector state: "+next.error());
        config=std::move(*next);
        return {};
    }
}
