// Portable nexus://share/v1/<base64url> workspace profile bundle export & import.
module provider.workspace_compose;
import std;
import crypto;
import encoding.base64;
import encoding.hex;
import glaze;
import :detail;

namespace provider {
    using namespace ws_detail;

    namespace {
        constexpr std::string_view kSharePrefix = "nexus://share/v1/";
        constexpr std::size_t kMaxWorkspaceBytes = 8u * 1024u * 1024u;
        constexpr std::size_t kMaxBundleBytes = 256u * 1024u;

        struct ShareBundle {
            int schema_version = 1;
            std::string kind = "bundle";
            std::vector<WorkspaceProfile> profiles;
            std::vector<std::string> root_ids;
        };

        auto url_b64_digit(char c) noexcept -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '-') return 62;
            if (c == '_') return 63;
            return -1;
        }

        auto decode_base64url_unpadded(std::string_view in) -> std::optional<std::string> {
            if (in.empty() || (in.size() % 4u) == 1u) return std::nullopt;
            std::string out;
            out.reserve((in.size() / 4u) * 3u + 3u);
            std::size_t i = 0;
            while (i + 4u <= in.size()) {
                int a = url_b64_digit(in[i]), b = url_b64_digit(in[i + 1]);
                int c = url_b64_digit(in[i + 2]), d = url_b64_digit(in[i + 3]);
                if (a < 0 || b < 0 || c < 0 || d < 0) return std::nullopt;
                out.push_back(static_cast<char>((a << 2) | (b >> 4)));
                out.push_back(static_cast<char>(((b & 15) << 4) | (c >> 2)));
                out.push_back(static_cast<char>(((c & 3) << 6) | d));
                i += 4u;
            }
            std::size_t rem = in.size() - i;
            if (rem == 2u) {
                int a = url_b64_digit(in[i]), b = url_b64_digit(in[i + 1]);
                if (a < 0 || b < 0 || (b & 15) != 0) return std::nullopt;
                out.push_back(static_cast<char>((a << 2) | (b >> 4)));
            } else if (rem == 3u) {
                int a = url_b64_digit(in[i]), b = url_b64_digit(in[i + 1]), c = url_b64_digit(in[i + 2]);
                if (a < 0 || b < 0 || c < 0 || (c & 3) != 0) return std::nullopt;
                out.push_back(static_cast<char>((a << 2) | (b >> 4)));
                out.push_back(static_cast<char>(((b & 15) << 4) | (c >> 2)));
            }
            return out;
        }

        auto is_shareable_kind(std::string_view k) noexcept -> bool {
            return k == "node" || k == "custom_outbound" || k == "policy_group" || k == "proxy_chain";
        }

        auto check_bundle_dag(
            std::map<std::string, WorkspaceProfile const*, std::less<>> const& by_id,
            std::string const& id,
            std::set<std::string>& visiting,
            std::set<std::string>& visited,
            std::vector<std::string>* order_out) -> std::expected<void, std::string> {
            auto it = by_id.find(id);
            if (it == by_id.end()) return std::unexpected("referenced profile not found: " + id);
            auto const& p = *it->second;
            if (p.kind == "full_custom_kdl" || !trim(p.full_custom_kdl).empty())
                return std::unexpected("full_custom_kdl profiles are forbidden in nexus:// share bundles: " + id);
            if (!is_shareable_kind(p.kind))
                return std::unexpected("unsupported profile kind '" + p.kind + "' on " + id);
            if (visited.contains(id)) return {};
            if (!visiting.insert(id).second)
                return std::unexpected("profile dependency cycle detected at: " + id);

            if (p.kind == "proxy_chain") {
                if (p.proxy_chain.hop_ids.empty())
                    return std::unexpected("proxy_chain has no hops: " + id);
                std::set<std::string> seen_hops;
                for (auto const& hid : p.proxy_chain.hop_ids) {
                    if (!seen_hops.insert(hid).second)
                        return std::unexpected("proxy_chain contains duplicate hop: " + hid);
                    if (auto ok = check_bundle_dag(by_id, hid, visiting, visited, order_out); !ok) return ok;
                }
            } else if (p.kind == "policy_group") {
                for (auto const& mid : p.policy_group.member_ids) {
                    if (auto ok = check_bundle_dag(by_id, mid, visiting, visited, order_out); !ok) return ok;
                }
            }
            visiting.erase(id);
            visited.insert(id);
            if (order_out) order_out->push_back(id);
            return {};
        }

        auto make_fresh_id(std::set<std::string>& existing) -> std::expected<std::string, std::string> {
            for (int tries = 0; tries < 64; ++tries) {
                std::array<std::uint8_t, 6> rnd{};
                if (!crypto::random_bytes(rnd)) return std::unexpected("random_bytes failed");
                auto id = "sh-" + encoding::hex_encode(rnd);
                if (existing.insert(id).second) return id;
            }
            return std::unexpected("failed to allocate unique profile id");
        }
    }

    auto export_workspace_share(
        std::string_view workspace_json,
        std::vector<std::string> const& profile_ids) -> WorkspaceShareExportResult {
        WorkspaceShareExportResult res{};
        if (workspace_json.size() > kMaxWorkspaceBytes) {
            res.errors.push_back("workspace.json exceeds 8 MiB limit");
            return res;
        }
        if (profile_ids.empty()) {
            res.errors.push_back("at least one --id is required for export-share");
            return res;
        }
        Workspace ws{};
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(ws, workspace_json)) {
            res.errors.push_back("invalid workspace.json: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, workspace_json));
            return res;
        }
        if (ws.schema_version != 1) {
            res.errors.push_back("unsupported workspace schema_version");
            return res;
        }
        std::map<std::string, WorkspaceProfile const*, std::less<>> by_id;
        for (auto const& p : ws.profiles) if (!p.id.empty()) by_id.emplace(p.id, &p);

        std::set<std::string> visiting, visited;
        std::vector<std::string> order;
        for (auto const& id : profile_ids) {
            if (auto ok = check_bundle_dag(by_id, id, visiting, visited, &order); !ok) {
                res.errors.push_back(ok.error());
                return res;
            }
        }

        std::map<std::string, std::string, std::less<>> remap;
        for (std::size_t i = 0; i < order.size(); ++i)
            remap.emplace(order[i], "p" + std::to_string(i + 1));

        ShareBundle bundle{};
        bundle.profiles.reserve(order.size());
        for (auto const& orig_id : order) {
            WorkspaceProfile p = *by_id.at(orig_id);
            p.id = remap.at(orig_id);
            p.subscription_id.clear();
            p.is_from_sub = false;
            p.full_custom_kdl.clear();
            if (p.kind == "proxy_chain") {
                for (auto& hid : p.proxy_chain.hop_ids) hid = remap.at(hid);
            } else if (p.kind == "policy_group") {
                for (auto& mid : p.policy_group.member_ids) mid = remap.at(mid);
                if (!p.policy_group.dynamic_sub_id.empty()) p.policy_group.dynamic_sub_id = "self";
            }
            bundle.profiles.push_back(std::move(p));
        }
        std::set<std::string> seen_roots;
        for (auto const& id : profile_ids) {
            auto const& mapped = remap.at(id);
            if (seen_roots.insert(mapped).second) bundle.root_ids.push_back(mapped);
        }

        auto encoded = glaze::write_json(bundle);
        if (!encoded) {
            res.errors.push_back("failed to serialize share bundle JSON");
            return res;
        }
        if (encoded->size() > kMaxBundleBytes) {
            res.errors.push_back("share bundle exceeds 256 KiB limit");
            return res;
        }
        auto bytes = std::span<std::uint8_t const>(
            reinterpret_cast<std::uint8_t const*>(encoded->data()), encoded->size());
        res.uri = std::string(kSharePrefix) + encoding::encode_base64url(bytes, false);
        res.exported_count = bundle.profiles.size();
        res.ok = true;
        return res;
    }

    auto import_workspace_share(
        std::string_view workspace_json,
        std::string_view share_uri,
        std::string_view target_subscription_id) -> WorkspaceShareImportResult {
        WorkspaceShareImportResult res{};
        if (workspace_json.size() > kMaxWorkspaceBytes) {
            res.errors.push_back("workspace.json exceeds 8 MiB limit");
            return res;
        }
        Workspace ws{};
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(ws, workspace_json)) {
            res.errors.push_back("invalid workspace.json: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, workspace_json));
            return res;
        }
        if (ws.schema_version != 1) {
            res.errors.push_back("unsupported workspace schema_version");
            return res;
        }
        auto uri = trim(share_uri);
        if (!uri.starts_with(kSharePrefix)) {
            res.errors.push_back("share URI must start with nexus://share/v1/");
            return res;
        }
        auto payload_b64 = uri.substr(kSharePrefix.size());
        constexpr std::size_t kMaxB64Len = ((kMaxBundleBytes + 2u) / 3u) * 4u;
        if (payload_b64.empty() || payload_b64.size() > kMaxB64Len) {
            res.errors.push_back("share bundle payload is empty or exceeds 256 KiB limit");
            return res;
        }
        auto decoded = decode_base64url_unpadded(payload_b64);
        if (!decoded) {
            res.errors.push_back("invalid base64url encoding in share URI");
            return res;
        }
        if (decoded->size() > kMaxBundleBytes) {
            res.errors.push_back("decoded share bundle exceeds 256 KiB limit");
            return res;
        }
        if (!is_valid_utf8(*decoded)) {
            res.errors.push_back("share bundle is not valid UTF-8");
            return res;
        }

        ShareBundle bundle{};
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(bundle, *decoded)) {
            res.errors.push_back("invalid share bundle JSON: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, *decoded));
            return res;
        }
        if (bundle.schema_version != 1 || bundle.kind != "bundle" || bundle.profiles.empty()) {
            res.errors.push_back("invalid share bundle schema_version, kind, or empty profiles");
            return res;
        }

        std::map<std::string, WorkspaceProfile const*, std::less<>> by_id;
        for (auto const& p : bundle.profiles) {
            if (p.id.empty() || !by_id.emplace(p.id, &p).second) {
                res.errors.push_back("share bundle contains missing or duplicate profile id");
                return res;
            }
            if (p.kind == "full_custom_kdl" || !trim(p.full_custom_kdl).empty()) {
                res.errors.push_back("full_custom_kdl profiles are forbidden in nexus:// share bundles: " + p.id);
                return res;
            }
            if (!is_shareable_kind(p.kind)) {
                res.errors.push_back("unsupported profile kind '" + p.kind + "' in share bundle");
                return res;
            }
        }
        std::set<std::string> visiting, visited;
        for (auto const& p : bundle.profiles) {
            if (auto ok = check_bundle_dag(by_id, p.id, visiting, visited, nullptr); !ok) {
                res.errors.push_back(ok.error());
                return res;
            }
        }

        std::set<std::string> existing_ids;
        for (auto const& p : ws.profiles) if (!p.id.empty()) existing_ids.insert(p.id);
        std::map<std::string, std::string, std::less<>> remap;
        for (auto const& p : bundle.profiles) {
            auto fresh = make_fresh_id(existing_ids);
            if (!fresh) { res.errors.push_back(fresh.error()); return res; }
            remap.emplace(p.id, std::move(*fresh));
        }

        for (auto p : bundle.profiles) {
            p.id = remap.at(p.id);
            p.subscription_id.clear();
            p.is_from_sub = false;
            p.full_custom_kdl.clear();
            if (p.kind == "proxy_chain") {
                for (auto& hid : p.proxy_chain.hop_ids) hid = remap.at(hid);
            } else if (p.kind == "policy_group") {
                for (auto& mid : p.policy_group.member_ids) mid = remap.at(mid);
                if (p.policy_group.dynamic_sub_id == "self") {
                    if (!target_subscription_id.empty()) {
                        p.policy_group.dynamic_sub_id = std::string(target_subscription_id);
                    } else {
                        p.policy_group.dynamic_sub_id.clear();
                        res.warnings.push_back("cleared dynamic_sub_id 'self' on imported policy_group: no subscription_id provided");
                    }
                } else if (!p.policy_group.dynamic_sub_id.empty()) {
                    p.policy_group.dynamic_sub_id.clear();
                    res.warnings.push_back("cleared non-self dynamic_sub_id on imported policy_group");
                }
            }
            ws.profiles.push_back(std::move(p));
        }

        std::set<std::string> seen_out;
        for (auto const& rid : bundle.root_ids) {
            if (auto it = remap.find(rid); it != remap.end() && seen_out.insert(it->second).second)
                res.imported_ids.push_back(it->second);
        }
        for (auto const& p : bundle.profiles) {
            auto const& nid = remap.at(p.id);
            if (seen_out.insert(nid).second) res.imported_ids.push_back(nid);
        }

        auto out_json = glaze::write_json(ws);
        if (!out_json) {
            res.errors.push_back("failed to serialize updated workspace.json");
            return res;
        }
        res.workspace_json = std::move(*out_json);
        res.ok = true;
        return res;
    }

    auto serialize_share_export_result_json(WorkspaceShareExportResult const& r) -> std::string {
        std::string out = "{\"ok\":";
        out += r.ok ? "true" : "false";
        out += ",\"uri\":"; out += json_quote(r.uri);
        out += ",\"exported_count\":"; out += std::to_string(r.exported_count);
        out += ",\"warnings\":"; append_json_string_array(out, r.warnings);
        out += ",\"errors\":"; append_json_string_array(out, r.errors);
        out += "}\n";
        return out;
    }

    auto serialize_share_import_result_json(WorkspaceShareImportResult const& r) -> std::string {
        std::string out = "{\"ok\":";
        out += r.ok ? "true" : "false";
        out += ",\"imported_ids\":"; append_json_string_array(out, r.imported_ids);
        out += ",\"warnings\":"; append_json_string_array(out, r.warnings);
        out += ",\"errors\":"; append_json_string_array(out, r.errors);
        out += ",\"workspace_json\":"; out += json_quote(r.workspace_json);
        out += "}\n";
        return out;
    }
}
