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
        auto write_provider_secret(ConvertOptions const& opts, std::set<std::string>& used_secrets,
            std::string_view hint, std::string_view content, bool* wrote_file)
            -> std::expected<std::string, std::string> {
            if (wrote_file) *wrote_file = false;
            std::string clean = sanitize_tag(hint, "secret");
            std::string unique = clean;
            for (std::size_t n = 2; !used_secrets.insert(unique).second; ++n)
                unique = clean + "-" + std::to_string(n);
            if (opts.inline_placeholders || opts.secrets_dir.empty())
                return "/etc/nexus/secrets/" + unique + ".secret";
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
            auto base = unique + ".secret";
            auto path = dir / base;
            static std::atomic<std::uint64_t> seq{0};
            auto tmp = std::format(".{}.tmp.{}.{}", base, ::getpid(), seq.fetch_add(1, std::memory_order_relaxed));
            int fd = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) return std::unexpected("cannot create secret file: " + path.string());
            auto drop = [&] { ::close(fd); (void)::unlinkat(dfd, tmp.c_str(), 0); };
            if (::fchmod(fd, 0600) != 0) { drop(); return std::unexpected("cannot chmod secret file: " + path.string()); }
            for (std::size_t off = 0; off < content.size();) {
                auto n = ::write(fd, content.data() + off, content.size() - off);
                if (n <= 0) { if (n < 0 && errno == EINTR) continue; drop(); return std::unexpected("cannot write secret file: " + path.string()); }
                off += static_cast<std::size_t>(n);
            }
            if (::close(fd) != 0 || ::renameat(dfd, tmp.c_str(), dfd, base.c_str()) != 0) {
                (void)::unlinkat(dfd, tmp.c_str(), 0);
                return std::unexpected("cannot install secret file: " + path.string());
            }
            if (wrote_file) *wrote_file = true;
            return path.string();
#else
            std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
            auto path = dir / (unique + ".secret");
            std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!out) return std::unexpected("cannot write secret file: " + path.string());
            out.write(content.data(), static_cast<std::streamsize>(content.size()));
            out.close();
            if (!out) return std::unexpected("cannot flush secret file: " + path.string());
            std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                         std::filesystem::perm_options::replace, ec);
            if (wrote_file) *wrote_file = true;
            return path.string();
#endif
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
            std::vector<std::string> node_secrets;
            SecretWriter writer = [&](std::string_view hint, std::string_view content) -> std::expected<std::string, std::string> {
                bool wrote = false;
                auto res = detail::write_provider_secret(opts, used_secrets, hint, content, &wrote);
                if (res && wrote) node_secrets.push_back(*res);
                return res;
            };
            auto kdl = emit_outbound_kdl(p, writer, fallback_ca);
            if (!kdl) {
                std::error_code ec;
                for (auto const& sf : node_secrets) std::filesystem::remove(sf, ec);
                doc.warnings.push_back(kdl.error());
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

        std::set<std::string> existing_outbounds;
        glaze::KdlNode* outbounds_node = nullptr;
        auto scan_existing = [&](glaze::KdlNode const& n) {
            auto tag = outbound_name(n);
            if (!tag.empty()) existing_outbounds.insert(tag);
        };
        for (auto& top : *doc) {
            if (top.name == "outbounds") {
                if (!outbounds_node) outbounds_node = &top;
                for (auto const& ch : top.children) scan_existing(ch);
            } else if (top.name == "outbound" || top.name == "direct" || top.name == "block") {
                scan_existing(top);
            }
        }
        if (!outbounds_node) {
            doc->push_back(glaze::KdlNode{.name = "outbounds"});
            outbounds_node = &doc->back();
        }
        for (auto const& [pname, items] : provider_outbounds_kdl) {
            (void)pname;
            for (auto const& [tag, kdl] : items) {
                if (!existing_outbounds.insert(tag).second) continue;
                auto sub = glaze::read_kdl<glaze::KdlDocument>(kdl);
                if (!sub || sub->empty()) return std::unexpected("internal error parsing provider outbound " + tag);
                for (auto& ob : *sub) outbounds_node->children.push_back(std::move(ob));
            }
        }

        auto expand_group = [&](glaze::KdlNode& group) {
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
            if (!is_group) return;
            std::set<std::string> seen_members;
            std::vector<glaze::KdlNode> next_children;
            for (auto& c : group.children) {
                if (c.name == "member" || c.name == "members") {
                    for (auto const& a : c.arguments) if (auto* s = node_str(a)) seen_members.insert(*s);
                    next_children.push_back(std::move(c));
                } else if (c.name == "use") {
                    for (auto const& a : c.arguments) {
                        auto* pn = node_str(a);
                        if (!pn) continue;
                        if (auto it = provider_outbounds_kdl.find(*pn); it != provider_outbounds_kdl.end()) {
                            for (auto const& [tag, _] : it->second) {
                                if (seen_members.insert(tag).second) {
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
        };

        for (auto& top : *doc) {
            if (top.name == "outbounds") {
                for (auto& ch : top.children) expand_group(ch);
            } else if (top.name == "outbound") {
                expand_group(top);
            }
        }
        auto written = glaze::write_kdl(*doc);
        if (!written) return std::unexpected("cannot serialize expanded KDL configuration");
        return *written;
    }
}
