// Shared local / inline / remote rule-set parsing for routing and DNS.
#pragma once

        inline auto valid_sha256_hex(std::string_view text) noexcept -> bool {
            if (text.size()!=64) return false;
            return std::ranges::all_of(text,[](char c) {
                return (c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F');
            });
        }

        inline auto parse_rule_set_spec(Node const& child) -> std::expected<std::pair<std::string,BlockRules>,std::string> {
            auto name=argument(child);
            if (!name || !valid_name(*name)) return error("invalid rule-set name");
            auto type=text_property(child,"type");
            auto path=text_property(child,"path");
            auto url=text_property(child,"url");
            auto format=text_property(child,"format");
            auto client=text_property(child,"http-client");
            auto sha256=text_property(child,"sha256");
            auto interval_value=property(child,"update-interval-ms");
            auto interval=interval_value ? integer(*interval_value) : std::nullopt;
            if (!child.children.empty()) {
                if (child.properties.size()!=bool(type) || (type && *type!="inline"))
                    return error("inline rule-set accepts only optional type=\"inline\" and predicate children");
                rules::RuleSet predicates{.version=2};
                std::size_t predicate_count=0;
                for (auto const& operand : child.children) {
                    auto pred=rules::decode_kdl_predicate(operand,1,predicate_count);
                    if (!pred) return error(std::move(pred.error().message));
                    predicates.rules.push_back(std::move(*pred));
                }
                if (predicates.rules.size()>1) {
                    auto operands=std::move(predicates.rules);
                    predicates.rules={{"any",{},std::move(operands)}};
                }
                auto normalized=rules::normalize_set(std::move(predicates));
                if (!normalized) return error(std::move(normalized.error().message));
                BlockRules spec{};
                spec.format=RuleFormat::kdl;
                spec.inline_rules=std::move(*normalized);
                g::KdlDocument doc;
                g::KdlNode ver;
                ver.name="version";
                ver.arguments.push_back(g::KdlValue{std::int64_t{2}});
                doc.push_back(std::move(ver));
                for (auto const& c : child.children) doc.push_back(c);
                if (auto encoded=g::write_kdl(doc)) spec.inline_kdl=std::move(*encoded);
                return std::pair{*name,std::move(spec)};
            }
            if (url) {
                if (path || (type && *type!="remote") || !url->starts_with("https://") || url->size()>2048 ||
                    url->contains('\0') || !format || (*format!="kdl" && *format!="beve" && *format!="srs") ||
                    (client && !valid_name(*client)) || (sha256 && !valid_sha256_hex(*sha256)) ||
                    (interval_value && (!interval || *interval<1000 || *interval>86400000)) ||
                    child.properties.size()!=2u+bool(type)+bool(client)+bool(sha256)+bool(interval_value))
                    return error("invalid remote rule-set");
                BlockRules spec{};
                spec.format=*format=="kdl" ? RuleFormat::kdl : *format=="beve" ? RuleFormat::beve : RuleFormat::srs;
                spec.url=*url;
                if (client) spec.http_client=*client;
                if (sha256) spec.sha256=*sha256;
                spec.update_interval_ms=static_cast<std::uint32_t>(interval.value_or(3600000));
                return std::pair{*name,std::move(spec)};
            }
            if ((type && *type!="local") || !path || path->empty() || path->contains('\0') || !format ||
                (*format!="kdl" && *format!="beve" && *format!="srs") ||
                child.properties.size()!=2u+bool(type))
                return error("invalid rule-set");
            BlockRules spec{};
            spec.path=*path;
            spec.format=*format=="kdl" ? RuleFormat::kdl : *format=="beve" ? RuleFormat::beve : RuleFormat::srs;
            return std::pair{*name,std::move(spec)};
        }
