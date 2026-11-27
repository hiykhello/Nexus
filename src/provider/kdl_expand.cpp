module;
#if !defined(_WIN32)
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

module provider;
import std;
import glaze;
import :detail;

namespace provider {
    namespace detail {
        auto stage_provider_secret(ConvertOptions const& opts,
            std::set<std::string> const& committed_secrets, std::set<std::string>& pending_secrets,
            std::vector<StagedSecret>& staged, std::string_view hint, std::string_view content)
            -> std::expected<std::string, std::string> {
            std::string clean = sanitize_tag(hint, "secret");
            std::string unique = clean;
            for (std::size_t n = 2; committed_secrets.contains(unique) || pending_secrets.contains(unique); ++n)
                unique = clean + "-" + std::to_string(n);
            pending_secrets.insert(unique);
            if (opts.inline_placeholders || opts.secrets_dir.empty()) {
                auto path = "/etc/nexus/secrets/" + unique + ".secret";
                staged.push_back({std::move(unique), path, {}});
                return path;
            }
            std::error_code ec;
            auto dir = std::filesystem::weakly_canonical(opts.secrets_dir, ec);
            if (ec) dir = std::filesystem::absolute(opts.secrets_dir, ec);
            if (ec) return std::unexpected("cannot resolve secrets-dir: " + ec.message());
            auto path = (dir / (unique + ".secret")).string();
            staged.push_back({std::move(unique), path, std::string(content)});
            return path;
        }

        auto commit_provider_secrets(ConvertOptions const& opts,
            std::set<std::string>& committed_secrets, std::vector<StagedSecret> const& staged,
            std::vector<std::string>* written_paths)
            -> std::expected<void, std::string> {
            if (staged.empty()) return {};
            if (opts.inline_placeholders || opts.secrets_dir.empty()) {
                for (auto const& s : staged) committed_secrets.insert(s.unique);
                return {};
            }
            std::error_code ec;
            auto dir = std::filesystem::weakly_canonical(opts.secrets_dir, ec);
            if (ec) dir = std::filesystem::absolute(opts.secrets_dir, ec);
            std::filesystem::create_directories(dir, ec);
            if (ec) return std::unexpected("cannot create secrets-dir: " + ec.message());
#if !defined(_WIN32)
            int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (dfd < 0) return std::unexpected("cannot open secrets-dir safely: " + dir.string());
            struct DirFd { int fd; ~DirFd() { if (fd >= 0) ::close(fd); } } d{dfd};
            struct stat st{};
            if (::fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || ::fchmod(dfd, 0700) != 0)
                return std::unexpected("unsafe secrets-dir ownership or permissions: " + dir.string());
            static std::atomic<std::uint64_t> seq{0};
            std::vector<std::pair<std::string, std::string>> temps;
            temps.reserve(staged.size());
            auto cleanup_temps = [&](std::size_t from = 0) noexcept {
                for (std::size_t i = from; i < temps.size(); ++i)
                    (void)::unlinkat(dfd, temps[i].first.c_str(), 0);
            };
            for (auto const& s : staged) {
                auto base = s.unique + ".secret";
                auto tmp = std::format(".{}.tmp.{}.{}", base, ::getpid(), seq.fetch_add(1, std::memory_order_relaxed));
                int fd = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                if (fd < 0) { cleanup_temps(); return std::unexpected("cannot create secret file: " + s.path); }
                auto drop = [&] { ::close(fd); (void)::unlinkat(dfd, tmp.c_str(), 0); cleanup_temps(); };
                if (::fchmod(fd, 0600) != 0) { drop(); return std::unexpected("cannot chmod secret file: " + s.path); }
                for (std::size_t off = 0; off < s.content.size();) {
                    auto n = ::write(fd, s.content.data() + off, s.content.size() - off);
                    if (n <= 0) { if (n < 0 && errno == EINTR) continue; drop(); return std::unexpected("cannot write secret file: " + s.path); }
                    off += static_cast<std::size_t>(n);
                }
                if (::close(fd) != 0) { (void)::unlinkat(dfd, tmp.c_str(), 0); cleanup_temps(); return std::unexpected("cannot close secret file: " + s.path); }
                temps.emplace_back(std::move(tmp), std::move(base));
            }
            for (std::size_t i = 0; i < temps.size(); ++i) {
                if (::renameat(dfd, temps[i].first.c_str(), dfd, temps[i].second.c_str()) != 0) {
                    cleanup_temps(i);
                    return std::unexpected("cannot install secret file: " + staged[i].path);
                }
            }
#else
            std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
            static std::atomic<std::uint64_t> seq{0};
            std::vector<std::pair<std::filesystem::path, std::filesystem::path>> temps;
            temps.reserve(staged.size());
            auto cleanup_temps = [&](std::size_t from = 0) noexcept {
                std::error_code rm_ec;
                for (std::size_t i = from; i < temps.size(); ++i) std::filesystem::remove(temps[i].first, rm_ec);
            };
            for (auto const& s : staged) {
                auto final_p = dir / (s.unique + ".secret");
                auto tmp_p = dir / std::format(".{}.secret.tmp.{}", s.unique, seq.fetch_add(1, std::memory_order_relaxed));
                std::ofstream out(tmp_p, std::ios::out | std::ios::binary | std::ios::trunc);
                if (!out) { cleanup_temps(); return std::unexpected("cannot write secret file: " + s.path); }
                out.write(s.content.data(), static_cast<std::streamsize>(s.content.size()));
                out.close();
                if (!out) { std::error_code rm_ec; std::filesystem::remove(tmp_p, rm_ec); cleanup_temps(); return std::unexpected("cannot flush secret file: " + s.path); }
                std::filesystem::permissions(tmp_p, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                             std::filesystem::perm_options::replace, ec);
                temps.emplace_back(std::move(tmp_p), std::move(final_p));
            }
            for (std::size_t i = 0; i < temps.size(); ++i) {
                std::filesystem::rename(temps[i].first, temps[i].second, ec);
                if (ec) { cleanup_temps(i); return std::unexpected("cannot install secret file: " + staged[i].path); }
            }
#endif
            for (auto const& s : staged) {
                committed_secrets.insert(s.unique);
                if (written_paths) written_paths->push_back(s.path);
            }
            return {};
        }
    }

    auto convert_config_to_nodes_json(std::string_view input, ConvertOptions const& opts)
        -> std::expected<std::pair<std::string, std::vector<std::string>>, std::string> {
        auto parsed = parse_subscription(input, opts.format);
        if (!parsed) return std::unexpected(parsed.error());
        auto doc = std::move(*parsed);
        if (auto ok = apply_filter(doc.proxies, opts.filter); !ok) return std::unexpected(ok.error());
        if (doc.proxies.empty()) return std::unexpected("no matching proxies after filtering");

        auto dedent_two = [](std::string_view src) -> std::string {
            std::string out;
            out.reserve(src.size());
            std::size_t pos = 0;
            while (pos < src.size()) {
                auto nl = src.find('\n', pos);
                auto end = (nl == std::string_view::npos) ? src.size() : (nl + 1);
                auto line = src.substr(pos, end - pos);
                if (line.starts_with("  ")) line.remove_prefix(2);
                out.append(line);
                pos = end;
            }
            return out;
        };

        std::set<std::string> used_secrets;
        std::string fallback_ca = !opts.ca_file.empty() ? opts.ca_file : opts.filter.ca_file;
        std::string json = "{\"nodes\":[";
        std::size_t emitted = 0;
        bool any_insecure = false;
        for (auto const& p : doc.proxies) {
            if (p.skip_cert_verify) any_insecure = true;
            std::set<std::string> pending_secrets;
            std::vector<detail::StagedSecret> staged_secrets;
            SecretWriter writer = [&](std::string_view hint, std::string_view content) -> std::expected<std::string, std::string> {
                return detail::stage_provider_secret(opts, used_secrets, pending_secrets, staged_secrets, hint, content);
            };
            auto kdl = emit_outbound_kdl(p, writer, fallback_ca);
            if (!kdl) {
                doc.warnings.push_back(kdl.error());
                continue;
            }
            std::vector<std::string> node_secrets;
            if (auto committed = detail::commit_provider_secrets(opts, used_secrets, staged_secrets, &node_secrets); !committed) {
                doc.warnings.push_back(committed.error());
                continue;
            }
            if (emitted++) json.push_back(',');
            auto standalone = dedent_two(*kdl);
            std::string_view primary_secret = node_secrets.empty() ? std::string_view{} : std::string_view(node_secrets.front());
            json += "{\"tag\":";
            json += detail::json_escape(p.tag);
            json += ",\"protocol\":";
            json += detail::json_escape(detail::protocol_kdl_name(p.protocol));
            json += ",\"host\":";
            json += detail::json_escape(p.host);
            json += ",\"port\":";
            json += std::to_string(p.port);
            json += ",\"secret_file\":";
            json += detail::json_escape(primary_secret);
            json += ",\"secret_files\":[";
            for (std::size_t i = 0; i < node_secrets.size(); ++i) {
                if (i) json.push_back(',');
                json += detail::json_escape(node_secrets[i]);
            }
            json += "],\"kdl\":";
            json += detail::json_escape(standalone);
            json.push_back('}');
        }
        if (emitted == 0) return std::unexpected("no valid proxies could be emitted");
        if (any_insecure)
            doc.warnings.push_back("upstream skip-cert-verify/insecure was upgraded to verified TLS (specify --ca-file or trust system CAs)");
        json += "]}\n";
        return std::pair{std::move(json), std::move(doc.warnings)};
    }

    auto expand_providers_in_kdl(
        std::string_view raw_kdl,
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> const& provider_outbounds_kdl)
        -> std::expected<std::string, std::string> {
        auto doc = glaze::read_kdl<glaze::KdlDocument>(raw_kdl);
        if (!doc) return std::unexpected(glaze::format_error(doc.error(), raw_kdl));
        std::erase_if(*doc, [](glaze::KdlNode const& n) {
            return n.name == "proxy-providers" || n.name == "proxy-provider";
        });

        auto node_str = [](glaze::KdlValue const& v) -> std::string const* {
            return v.tag ? nullptr : std::get_if<std::string>(&v.data);
        };
        auto outbound_name = [&](glaze::KdlNode const& n) -> std::string {
            if (!n.tag && n.arguments.size() == 1)
                if (auto* s = node_str(n.arguments.front())) return *s;
            return {};
        };

        std::set<std::string> static_outbounds;
        glaze::KdlNode* outbounds_node = nullptr;
        auto scan_existing = [&](glaze::KdlNode const& n) {
            auto tag = outbound_name(n);
            if (!tag.empty()) static_outbounds.insert(tag);
            else if (n.name == "direct" || n.name == "block") static_outbounds.insert(n.name);
        };
        for (auto& top : *doc) {
            if (top.name == "outbounds") {
                if (!outbounds_node) outbounds_node = &top;
                for (auto const& ch : top.children) scan_existing(ch);
            } else if (top.name == "outbound" || top.name == "direct" || top.name == "block" ||
                       top.name == "selector" || top.name == "fallback" ||
                       top.name == "url-test" || top.name == "load-balance") {
                scan_existing(top);
            }
        }
        if (!outbounds_node) {
            doc->push_back(glaze::KdlNode{.name = "outbounds"});
            outbounds_node = &doc->back();
        }

        std::map<std::string, std::size_t> provider_tag_counts;
        for (auto const& [pname, items] : provider_outbounds_kdl) {
            (void)pname;
            for (auto const& [tag, _] : items) ++provider_tag_counts[tag];
        }
        std::set<std::string> ambiguous_tags;
        for (auto const& [tag, count] : provider_tag_counts) {
            if (count > 1 && !static_outbounds.contains(tag)) ambiguous_tags.insert(tag);
        }
        std::set<std::string> reserved_tags = static_outbounds;
        for (auto const& [tag, count] : provider_tag_counts) {
            if (count == 1 && !static_outbounds.contains(tag)) reserved_tags.insert(tag);
        }

        std::map<std::string, std::vector<std::string>> provider_effective_tags;
        for (auto const& [pname, items] : provider_outbounds_kdl) {
            std::vector<std::string> eff_tags;
            eff_tags.reserve(items.size());
            std::map<std::string, std::string> local_rename;
            std::string prefix = detail::sanitize_tag(pname, "provider");
            for (auto const& [orig_tag, _] : items) {
                std::string eff;
                if (!static_outbounds.contains(orig_tag) && provider_tag_counts[orig_tag] == 1) {
                    eff = orig_tag;
                } else {
                    std::string stem = prefix + "-" + orig_tag;
                    if (stem.size() > 240) stem.resize(240);
                    eff = stem;
                    for (std::size_t n = 2; !reserved_tags.insert(eff).second; ++n)
                        eff = stem + "-" + std::to_string(n);
                    local_rename.try_emplace(orig_tag, eff);
                }
                eff_tags.push_back(std::move(eff));
            }
            for (std::size_t i = 0; i < items.size(); ++i) {
                auto const& [orig_tag, kdl] = items[i];
                auto const& eff_tag = eff_tags[i];
                auto sub = glaze::read_kdl<glaze::KdlDocument>(kdl);
                if (!sub || sub->empty()) return std::unexpected("internal error parsing provider outbound " + orig_tag);
                for (auto& ob : *sub) {
                    if (eff_tag != orig_tag && ob.name == "outbound" && !ob.arguments.empty())
                        ob.arguments.front().data = eff_tag;
                    if (!local_rename.empty()) {
                        for (auto& ch : ob.children) {
                            if (ch.name == "detour" && ch.arguments.size() == 1) {
                                if (auto* ds = node_str(ch.arguments.front())) {
                                    if (auto rit = local_rename.find(*ds); rit != local_rename.end())
                                        ch.arguments.front().data = rit->second;
                                }
                            }
                        }
                    }
                    outbounds_node->children.push_back(std::move(ob));
                }
            }
            provider_effective_tags.emplace(pname, std::move(eff_tags));
        }

        auto expand_group = [&](glaze::KdlNode& group) -> std::expected<void, std::string> {
            bool is_group = group.name == "selector" || group.name == "fallback" ||
                            group.name == "url-test" || group.name == "load-balance";
            if (!is_group && group.name == "outbound") {
                for (auto const& [k, v] : group.properties) {
                    if (k == "type") {
                        if (auto* ts = node_str(v); ts && (*ts == "selector" || *ts == "fallback" ||
                            *ts == "url-test" || *ts == "load-balance")) is_group = true;
                    }
                }
            }
            if (!is_group) return {};
            std::set<std::string> seen_members;
            std::set<std::string> from_use;
            std::vector<glaze::KdlNode> next_children;
            for (auto& c : group.children) {
                if (c.name == "member" || c.name == "members") {
                    std::vector<glaze::KdlValue> kept_args;
                    kept_args.reserve(c.arguments.size());
                    for (auto& a : c.arguments) {
                        if (auto* s = node_str(a)) {
                            if (ambiguous_tags.contains(*s))
                                return std::unexpected("ambiguous outbound tag '" + *s +
                                    "' defined by multiple proxy-providers; set tag-prefix or reference via use");
                            if (from_use.contains(*s)) continue;
                            seen_members.insert(*s);
                        }
                        kept_args.push_back(std::move(a));
                    }
                    if (!kept_args.empty()) {
                        c.arguments = std::move(kept_args);
                        next_children.push_back(std::move(c));
                    }
                } else if (c.name == "selected") {
                    if (c.arguments.size() == 1) {
                        if (auto* s = node_str(c.arguments.front()); s && ambiguous_tags.contains(*s))
                            return std::unexpected("ambiguous outbound tag '" + *s +
                                "' defined by multiple proxy-providers; set tag-prefix or reference via use");
                    }
                    next_children.push_back(std::move(c));
                } else if (c.name == "use") {
                    for (auto const& a : c.arguments) {
                        auto* pn = node_str(a);
                        if (!pn) continue;
                        if (auto it = provider_effective_tags.find(*pn); it != provider_effective_tags.end()) {
                            for (auto const& tag : it->second) {
                                if (seen_members.insert(tag).second) {
                                    from_use.insert(tag);
                                    next_children.push_back(glaze::KdlNode{
                                        .name = "member",
                                        .arguments = {glaze::KdlValue{tag, {}}}});
                                }
                            }
                        }
                    }
                } else {
                    next_children.push_back(std::move(c));
                }
            }
            group.children = std::move(next_children);
            return {};
        };

        for (auto& top : *doc) {
            if (top.name == "outbounds") {
                for (auto& ch : top.children)
                    if (auto ok = expand_group(ch); !ok) return std::unexpected(ok.error());
            } else if (top.name == "outbound" || top.name == "selector" || top.name == "fallback" ||
                       top.name == "url-test" || top.name == "load-balance") {
                if (auto ok = expand_group(top); !ok) return std::unexpected(ok.error());
            }
        }
        auto written = glaze::write_kdl(*doc);
        if (!written) return std::unexpected("cannot serialize expanded KDL configuration");
        return *written;
    }
}
