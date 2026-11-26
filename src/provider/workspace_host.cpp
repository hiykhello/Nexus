// Stage 2 secret writer, Stage 3 wrappers, Stage 5 host adapter & Stage 6 template overlay.
module;
#if !defined(_WIN32)
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

module provider.workspace_compose;
import std;
import glaze;
import platform.ip_address;
import :detail;

namespace provider::ws_detail {
    auto ComposeContext::write_hashed_secret(std::string_view kind, std::string_view content, std::string_view ext)
        -> std::expected<std::string, std::string> {
        std::string hash = sha256_hex_16(content);
        std::string filename = sanitize_tag(kind, "sec") + "-" + hash + std::string(ext);
        if (opts.secrets_dir.empty()) return "/etc/nexus/secrets/" + filename;
        std::error_code ec;
        auto dir = std::filesystem::weakly_canonical(opts.secrets_dir, ec);
        if (ec) dir = std::filesystem::absolute(opts.secrets_dir, ec);
        std::filesystem::create_directories(dir, ec);
        if (ec) return std::unexpected("cannot create secrets-dir: " + ec.message());
        auto full_path = dir / filename;
        bool existed = std::filesystem::exists(full_path, ec) && !ec;
#if !defined(_WIN32)
        int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dfd < 0) return std::unexpected("cannot open secrets-dir safely: " + dir.string());
        struct DirFd { int fd; ~DirFd() { if (fd >= 0) ::close(fd); } } d{dfd};
        struct stat st{};
        if (::fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() || ::fchmod(dfd, 0700) != 0)
            return std::unexpected("unsafe secrets-dir ownership or permissions: " + dir.string());
        static std::atomic<std::uint64_t> seq{0};
        auto tmp = std::format(".{}.tmp.{}.{}", filename, ::getpid(), seq.fetch_add(1, std::memory_order_relaxed));
        int fd = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return std::unexpected("cannot create secret file: " + full_path.string());
        auto drop = [&] { ::close(fd); (void)::unlinkat(dfd, tmp.c_str(), 0); };
        if (::fchmod(fd, 0600) != 0) { drop(); return std::unexpected("cannot chmod secret file: " + full_path.string()); }
        for (std::size_t off = 0; off < content.size();) {
            auto n = ::write(fd, content.data() + off, content.size() - off);
            if (n <= 0) { if (n < 0 && errno == EINTR) continue; drop(); return std::unexpected("cannot write secret file: " + full_path.string()); }
            off += static_cast<std::size_t>(n);
        }
        if (::close(fd) != 0 || ::renameat(dfd, tmp.c_str(), dfd, filename.c_str()) != 0) {
            (void)::unlinkat(dfd, tmp.c_str(), 0);
            return std::unexpected("cannot install secret file: " + full_path.string());
        }
#else
        std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
        std::ofstream out(full_path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out) return std::unexpected("cannot write secret file: " + full_path.string());
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.close();
        if (!out) return std::unexpected("cannot flush secret file: " + full_path.string());
        std::filesystem::permissions(full_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace, ec);
#endif
        auto path_str = full_path.string();
        if (!existed) created_secrets.push_back(path_str);
        if (secret_file_set.insert(path_str).second) secret_files.push_back(path_str);
        return path_str;
    }

    auto emit_direct_and_block(ComposeContext& ctx, std::ostringstream& out) -> void {
        out << "  outbound \"direct\" type=\"direct\" {\n";
        if (ctx.host.platform == "android") {
            if (!ctx.host.android.protect_socket_path.empty())
                out << "    protect-path " << kdl_quote(ctx.host.android.protect_socket_path) << '\n';
        } else if (ctx.host.platform.starts_with("desktop-")) {
            if (!ctx.host.desktop.bind_interface.empty())
                out << "    bind-interface " << kdl_quote(ctx.host.desktop.bind_interface) << '\n';
            if (!ctx.host.desktop.inet4_bind_address.empty())
                out << "    inet4-bind-address " << kdl_quote(ctx.host.desktop.inet4_bind_address) << '\n';
            if (!ctx.host.desktop.inet6_bind_address.empty())
                out << "    inet6-bind-address " << kdl_quote(ctx.host.desktop.inet6_bind_address) << '\n';
        }
        out << "  }\n  outbound \"block\" type=\"block\"\n";
    }

    auto emit_custom_outbound(ComposeContext& ctx, std::string_view raw_kdl, std::string_view tag,
                              std::string_view detour) -> std::expected<std::string, std::string> {
        std::string text(raw_kdl);
        auto replace_all = [](std::string& s, std::string_view from, std::string_view to) {
            for (std::size_t pos = 0; (pos = s.find(from, pos)) != std::string::npos; pos += to.size())
                s.replace(pos, from.size(), to);
        };
        replace_all(text, "{{tag}}", tag);
        replace_all(text, "{{detour}}", detour);
        auto doc = glaze::read_kdl<glaze::KdlDocument>(text);
        if (!doc || doc->size() != 1)
            return std::unexpected("custom_outbound_kdl must contain exactly one outbound node on " + std::string(tag));
        auto& node = doc->front();
        if (node.name != "outbound") {
            if (!std::ranges::any_of(node.properties, [](auto const& kv) { return kv.first == "type"; }))
                node.properties.push_back({"type", glaze::KdlValue{node.name, {}}});
            node.name = "outbound";
        }
        node.arguments = {glaze::KdlValue{std::string(tag), {}}};
        std::erase_if(node.children, [](auto const& c) {
            if (c.name != "detour" || c.arguments.size() != 1) return false;
            auto* s = std::get_if<std::string>(&c.arguments[0].data);
            return s && s->empty();
        });
        for (auto const& c : node.children)
            if (c.name == "server")
                for (auto const& [k, v] : c.properties)
                    if (k == "host") if (auto* s = std::get_if<std::string>(&v.data)) ctx.note_protect_host(*s);
        if (!detour.empty() && !std::ranges::any_of(node.children, [](auto const& c) { return c.name == "detour"; }))
            node.children.push_back(glaze::KdlNode{.name = "detour", .arguments = {glaze::KdlValue{std::string(detour), {}}}});
        auto rendered = glaze::write_kdl(*doc);
        if (!rendered) return std::unexpected("failed to serialize custom_outbound on " + std::string(tag));
        return *rendered;
    }

    auto emit_policy_group_outbound(ComposeContext&, WorkspaceProfile const& p, std::string_view tag,
                                    std::vector<std::string> const& member_tags) -> std::string {
        auto strat = lower_ascii(p.policy_group.strategy);
        if (strat != "selector" && strat != "url-test" && strat != "fallback" && strat != "load-balance") strat = "selector";
        std::ostringstream os;
        os << "  outbound " << kdl_quote(tag) << " type=" << kdl_quote(strat) << " {\n";
        for (auto const& m : member_tags) os << "    member " << kdl_quote(m) << '\n';
        if (strat == "selector" && !member_tags.empty()) os << "    selected " << kdl_quote(member_tags.front()) << '\n';
        if (strat == "url-test" || strat == "fallback" || strat == "load-balance") {
            auto url = p.policy_group.probe_url.empty() ? std::string_view("https://www.gstatic.com/generate_204")
                                                        : std::string_view(p.policy_group.probe_url);
            if (url.starts_with("http://") || url.starts_with("https://")) {
                os << "    probe-url " << kdl_quote(url) << '\n';
                auto iv = std::clamp<std::uint32_t>(p.policy_group.probe_interval_ms ? p.policy_group.probe_interval_ms : 300000, 500, 3600000);
                os << "    probe-interval-ms " << iv << '\n';
                if (strat == "url-test")
                    os << "    tolerance-ms " << std::clamp<std::uint32_t>(p.policy_group.tolerance_ms, 0, 10000) << '\n';
            }
        }
        os << "  }\n";
        return os.str();
    }

    auto emit_host_header(ComposeContext const& ctx, std::ostringstream& out) -> void {
        auto const& h = ctx.host;
        out << "schema-version 1\nrole \"client\"\n";
        if (!h.workers_spec.empty()) {
            out << "workers " << kdl_quote(h.workers_spec);
            if (h.workers_max >= 1) out << " max=" << h.workers_max;
            out << '\n';
        } else if (h.workers >= 1) out << "workers " << h.workers << '\n';
        if (!h.ca_file.empty()) out << "certificate {\n  ca-file " << kdl_quote(h.ca_file) << "\n}\n";
        else if (!ctx.resolved_ca_file.empty()) out << "certificate {\n  store \"system\"\n}\n";
        bool has_state = (!h.state_dir.empty() && h.state_dir.starts_with('/')) ||
                         (!h.cache_dir.empty() && h.cache_dir.starts_with('/'));
        if (has_state) {
            out << "state {\n";
            if (!h.state_dir.empty() && h.state_dir.starts_with('/')) out << "  directory " << kdl_quote(h.state_dir) << '\n';
            if (!h.cache_dir.empty() && h.cache_dir.starts_with('/')) out << "  cache-directory " << kdl_quote(h.cache_dir) << '\n';
            out << "}\n";
        }
        if (!h.control_socket.empty() || !h.control_http_listen.empty()) {
            out << "control";
            if (!h.control_socket.empty()) out << " socket=" << kdl_quote(h.control_socket);
            if (!h.control_http_listen.empty()) out << " http-listen=" << kdl_quote(h.control_http_listen) << " metrics=#true";
            if (!h.control_bearer_file.empty() && !h.control_http_listen.empty())
                out << " bearer-token-file=" << kdl_quote(h.control_bearer_file);
            out << '\n';
        }
        auto lvl = lower_ascii(h.log_level);
        if (lvl != "trace" && lvl != "debug" && lvl != "info" && lvl != "warn" && lvl != "error" && lvl != "off") lvl = "info";
        out << "log {\n  level " << kdl_quote(lvl) << '\n';
        if (!h.log_file.empty() && h.log_file.starts_with('/')) out << "  sink \"file\" path=" << kdl_quote(h.log_file) << '\n';
        out << "}\n";
    }

    auto emit_host_inbounds(ComposeContext& ctx, std::ostringstream& out) -> std::expected<void, std::string> {
        auto const& h = ctx.host;
        std::ostringstream ins;
        std::size_t count = 0;
        auto emit_mixed = [&](std::string_view name, std::string_view spec, std::string_view user, std::string_view pass)
            -> std::expected<void, std::string> {
            auto hp = platform::split_host_port(spec, true);
            if (!hp || !platform::parse_ip_address(hp->host))
                return std::unexpected("invalid listen endpoint '" + std::string(spec) + "' for " + std::string(name));
            ins << "  inbound " << kdl_quote(name) << " type=\"mixed\" {\n    listen host=" << kdl_quote(hp->host) << " port=" << hp->port << '\n';
            if (!user.empty() && !pass.empty()) {
                auto pf = ctx.write_hashed_secret("in-pass", pass);
                if (!pf) return std::unexpected(pf.error());
                ins << "    authentication \"password\" username=" << kdl_quote(user) << " password-file=" << kdl_quote(*pf) << '\n';
            } else {
                ins << "    authentication \"none\"\n";
            }
            ins << "  }\n";
            ++count;
            return {};
        };

        if (h.platform == "android") {
            auto mode = lower_ascii(h.android.run_mode);
            if (mode.empty()) mode = "vpn";
            if (mode == "vpn") {
                auto mtu = std::clamp<std::uint16_t>(h.android.tun_mtu ? h.android.tun_mtu : 1500, 68, 65535);
                ins << "  inbound \"tun-in\" type=\"tun\" {\n    stack \"system\"\n    mtu " << mtu
                    << "\n    endpoint-independent-nat #false\n  }\n";
                ++count;
            }
            if (h.android.enable_local_proxy || mode == "proxy_only") {
                auto listen = h.android.local_listen.empty() ? std::string_view("127.0.0.1:7890") : std::string_view(h.android.local_listen);
                if (auto ok = emit_mixed("local-mixed", listen, {}, {}); !ok) return ok;
            }
        } else if (h.platform == "ios") {
            ins << "  inbound \"tun-in\" type=\"tun\" {\n    device-mode \"bridge\"\n    stack \"system\"\n"
                << "    mtu 1500\n    endpoint-independent-nat #false\n  }\n";
            ++count;
        } else {
            auto const& d = h.desktop;
            bool is_linux = (h.platform == "desktop-linux");
            bool linux_strict = is_linux && d.enable_tun && d.tun_strict_route;
            auto emit_desktop_mixed = [&](std::string_view name, std::string_view label, std::string_view spec,
                                          std::string_view user, std::string_view pass) -> std::expected<void, std::string> {
                if (linux_strict) {
                    if (auto hp = platform::split_host_port(spec, true)) {
                        if (auto ip = platform::parse_ip_address(hp->host)) {
                            bool loopback = ip->size == 4
                                ? (ip->bytes[0] == 127)
                                : (std::ranges::all_of(std::span(ip->bytes).first(15), [](auto b) { return b == 0; }) && ip->bytes[15] == 1);
                            if (!loopback) {
                                ctx.warnings.push_back("desktop-linux TUN strict-route permits only loopback coexisting listeners; non-loopback " +
                                                       std::string(label) + " omitted");
                                return {};
                            }
                        }
                    }
                }
                return emit_mixed(name, spec, user, pass);
            };
            if (d.enable_mixed && !d.mixed_listen.empty())
                if (auto ok = emit_desktop_mixed("mixed-in", "mixed_listen", d.mixed_listen, {}, {}); !ok) return ok;
            if (!d.second_local_listen.empty())
                if (auto ok = emit_desktop_mixed("local-in-2", "second_local_listen", d.second_local_listen, {}, {}); !ok) return ok;
            if (!d.lan_listen.empty())
                if (auto ok = emit_desktop_mixed("lan-in", "lan_listen", d.lan_listen, d.lan_username, d.lan_password); !ok) return ok;
            if (d.enable_tun) {
                auto mtu = std::clamp<std::uint16_t>(d.tun_mtu ? d.tun_mtu : 1500, 68, 65535);
                ins << "  inbound \"tun-in\" type=\"tun\" {\n    stack \"system\"\n";
                if (!d.tun_interface_name.empty()) ins << "    interface-name " << kdl_quote(d.tun_interface_name) << '\n';
                ins << "    mtu " << mtu << '\n';
                if (!d.tun_inet4.empty()) ins << "    inet4-address " << kdl_quote(d.tun_inet4) << '\n';
                if (!d.tun_inet6.empty()) ins << "    inet6-address " << kdl_quote(d.tun_inet6) << '\n';
                bool auto_r = d.tun_auto_route || linux_strict;
                if (auto_r) ins << "    auto-route #true\n";
                if (linux_strict) ins << "    strict-route #true\n";
                if (ctx.fake_ip_active) ins << "    endpoint-independent-nat #false\n";
                if (is_linux ? linux_strict : auto_r) {
                    if (d.tun_route_exclude_private) ins << "    route-exclude-private #true\n";
                    for (auto const& ex : d.tun_route_exclude)
                        if ((ex.contains(':') && !d.tun_inet6.empty()) || (!ex.contains(':') && !d.tun_inet4.empty()))
                            ins << "    route-exclude " << kdl_quote(ex) << '\n';
                }
                ins << "  }\n";
                ++count;
            }
        }
        if (count == 0) return std::unexpected("host configuration enables no inbounds");
        out << "inbounds {\n" << ins.str() << "}\n";
        return {};
    }

    auto compose_full_custom_kdl(ComposeContext& ctx, WorkspaceProfile const& active) -> std::expected<std::string, std::string> {
        auto base_doc = glaze::read_kdl<glaze::KdlDocument>(active.full_custom_kdl);
        if (!base_doc) return std::unexpected("full_custom_kdl has invalid KDL syntax");
        auto upsert = [&](std::string_view kdl_snippet, std::string_view name) {
            auto sub = glaze::read_kdl<glaze::KdlDocument>(kdl_snippet);
            if (!sub || sub->empty()) return;
            auto it = std::ranges::find(*base_doc, name, &glaze::KdlNode::name);
            if (it != base_doc->end()) {
                *it = std::move(sub->front());
                base_doc->erase(std::remove_if(std::next(it), base_doc->end(), [&](auto const& n) { return n.name == name; }), base_doc->end());
            } else base_doc->push_back(std::move(sub->front()));
        };
        auto const& h = ctx.host;
        if (!h.workers_spec.empty()) {
            std::string w = "workers " + kdl_quote(h.workers_spec);
            if (h.workers_max >= 1) w += " max=" + std::to_string(h.workers_max);
            upsert(w + "\n", "workers");
        } else if (h.workers >= 1) upsert("workers " + std::to_string(h.workers) + "\n", "workers");
        if (!h.control_socket.empty() || !h.control_http_listen.empty()) {
            std::string c = "control";
            if (!h.control_socket.empty()) c += " socket=" + kdl_quote(h.control_socket);
            if (!h.control_http_listen.empty()) c += " http-listen=" + kdl_quote(h.control_http_listen) + " metrics=#true";
            if (!h.control_bearer_file.empty() && !h.control_http_listen.empty())
                c += " bearer-token-file=" + kdl_quote(h.control_bearer_file);
            upsert(c + "\n", "control");
        }
        if ((!h.state_dir.empty() && h.state_dir.starts_with('/')) || (!h.cache_dir.empty() && h.cache_dir.starts_with('/'))) {
            std::string s = "state {\n";
            if (!h.state_dir.empty() && h.state_dir.starts_with('/')) s += "  directory " + kdl_quote(h.state_dir) + "\n";
            if (!h.cache_dir.empty() && h.cache_dir.starts_with('/')) s += "  cache-directory " + kdl_quote(h.cache_dir) + "\n";
            upsert(s + "}\n", "state");
        }
        if (!h.log_level.empty() || !h.log_file.empty()) {
            auto lvl = lower_ascii(h.log_level);
            if (lvl != "trace" && lvl != "debug" && lvl != "info" && lvl != "warn" && lvl != "error" && lvl != "off") lvl = "info";
            std::string l = "log {\n  level " + kdl_quote(lvl) + "\n";
            if (!h.log_file.empty() && h.log_file.starts_with('/')) l += "  sink \"file\" path=" + kdl_quote(h.log_file) + "\n";
            upsert(l + "}\n", "log");
        }
        if (h.platform == "android") {
            auto is_tun = [](glaze::KdlNode const& n) {
                if (n.name == "tun") return true;
                if (n.name != "inbound") return false;
                for (auto const& [k, v] : n.properties)
                    if (k == "type") if (auto* s = std::get_if<std::string>(&v.data); s && *s == "tun") return true;
                return false;
            };
            std::erase_if(*base_doc, is_tun);
            std::size_t remaining_inbounds = 0;
            for (auto& n : *base_doc) {
                if (n.name == "inbounds") { std::erase_if(n.children, is_tun); remaining_inbounds += n.children.size(); }
                else if (n.name == "inbound" || n.name == "mixed" || n.name == "socks5" || n.name == "http") ++remaining_inbounds;
            }
            auto inject_inbound = [&](std::string const& snippet) {
                if (auto d = glaze::read_kdl<glaze::KdlDocument>(snippet); d && !d->empty()) {
                    auto grp = std::ranges::find(*base_doc, std::string_view("inbounds"), &glaze::KdlNode::name);
                    if (grp != base_doc->end()) grp->children.push_back(std::move(d->front()));
                    else base_doc->push_back(std::move(d->front()));
                }
            };
            if (lower_ascii(h.android.run_mode) != "proxy_only") {
                auto mtu = std::clamp<std::uint16_t>(h.android.tun_mtu ? h.android.tun_mtu : 1500, 68, 65535);
                inject_inbound("inbound \"tun-in\" type=\"tun\" { stack \"system\"; mtu " + std::to_string(mtu) + "; endpoint-independent-nat #false; }\n");
            } else if (remaining_inbounds == 0) {
                auto listen = h.android.local_listen.empty() ? std::string_view("127.0.0.1:7890") : std::string_view(h.android.local_listen);
                if (auto hp = platform::split_host_port(listen, true))
                    inject_inbound("inbound \"local-mixed\" type=\"mixed\" { listen host=" + kdl_quote(hp->host) +
                                   " port=" + std::to_string(hp->port) + "; authentication \"none\"; }\n");
            }
        }
        auto written = glaze::write_kdl(*base_doc);
        if (!written) return std::unexpected("failed to serialize overridden full_custom_kdl");
        return std::move(*written);
    }

    namespace {
        auto outbound_tag_and_type(glaze::KdlNode const& n) -> std::pair<std::string, std::string> {
            std::string tag, type;
            if (!n.arguments.empty()) if (auto* s = std::get_if<std::string>(&n.arguments[0].data)) tag = *s;
            if (n.name == "outbound") {
                for (auto const& [k, v] : n.properties)
                    if (k == "type") if (auto* s = std::get_if<std::string>(&v.data)) type = *s;
            } else {
                type = n.name;
                if (tag.empty() && (n.name == "direct" || n.name == "block")) tag = n.name;
            }
            return {tag, type};
        }

        auto is_vless_xhttp_node(glaze::KdlNode const& ob, std::string_view type) -> bool {
            if (type != "vless") return false;
            for (auto const& c : ob.children)
                if (c.name == "transport" && !c.arguments.empty())
                    if (auto* s = std::get_if<std::string>(&c.arguments[0].data); s && *s == "xhttp") return true;
            return false;
        }
    }

    auto apply_full_template(WorkspaceFullTemplate const& tmpl, std::string_view compiled_kdl)
        -> std::expected<std::string, std::string> {
        auto tdoc = glaze::read_kdl<glaze::KdlDocument>(tmpl.template_kdl);
        if (!tdoc) return std::unexpected("full_template.template_kdl has invalid KDL syntax");
        auto cdoc = glaze::read_kdl<glaze::KdlDocument>(compiled_kdl);
        if (!cdoc) return std::unexpected("internal error reading compiled KDL for template overlay");
        auto c_obs = std::ranges::find(*cdoc, std::string_view("outbounds"), &glaze::KdlNode::name);
        auto t_obs = std::ranges::find(*tdoc, std::string_view("outbounds"), &glaze::KdlNode::name);

        if (tmpl.append_proxies_only) {
            if (c_obs != cdoc->end()) {
                bool has_top = std::ranges::any_of(*tdoc, [](auto const& n) { return n.name == "outbound"; });
                std::set<std::string> existing;
                if (t_obs != tdoc->end()) {
                    for (auto const& ch : t_obs->children)
                        if (auto [nm, _] = outbound_tag_and_type(ch); !nm.empty()) existing.insert(nm);
                    for (auto const& ch : c_obs->children)
                        if (auto [nm, _] = outbound_tag_and_type(ch); !nm.empty() && existing.insert(nm).second)
                            t_obs->children.push_back(ch);
                } else if (has_top) {
                    for (auto const& n : *tdoc)
                        if (n.name == "outbound")
                            if (auto [nm, _] = outbound_tag_and_type(n); !nm.empty()) existing.insert(nm);
                    for (auto const& ch : c_obs->children)
                        if (auto [nm, _] = outbound_tag_and_type(ch); !nm.empty() && existing.insert(nm).second)
                            tdoc->push_back(ch);
                } else {
                    tdoc->push_back(*c_obs);
                }
            }
            auto out = glaze::write_kdl(*tdoc);
            return out ? std::expected<std::string, std::string>(std::move(*out)) : std::unexpected("failed to serialize template overlay");
        }

        std::set<std::string> template_tags;
        if (c_obs != cdoc->end()) {
            std::set<std::string> existing;
            for (auto const& ch : c_obs->children)
                if (auto [nm, _] = outbound_tag_and_type(ch); !nm.empty()) existing.insert(nm);
            auto import_ob = [&](glaze::KdlNode const& n) {
                auto [nm, _] = outbound_tag_and_type(n);
                if (!nm.empty() && existing.insert(nm).second) {
                    c_obs->children.push_back(n);
                    template_tags.insert(nm);
                }
            };
            if (t_obs != tdoc->end()) for (auto const& ch : t_obs->children) import_ob(ch);
            for (auto const& n : *tdoc) if (n.name == "outbound") import_ob(n);

            if (!tmpl.proxy_detour.empty()) {
                for (auto& ob : c_obs->children) {
                    auto [tag, type] = outbound_tag_and_type(ob);
                    if (tag == tmpl.proxy_detour || template_tags.contains(tag)) continue;
                    if (type == "direct" || type == "block" || type == "selector" || type == "url-test" ||
                        type == "fallback" || type == "load-balance" || is_vless_xhttp_node(ob, type)) continue;
                    if (!std::ranges::any_of(ob.children, [](auto const& c) { return c.name == "detour"; })) {
                        std::erase_if(ob.children, [](auto const& c) {
                            return c.name == "bind-interface" || c.name == "inet4-bind-address" ||
                                   c.name == "inet6-bind-address" || c.name == "protect-path";
                        });
                        ob.children.push_back(glaze::KdlNode{.name = "detour", .arguments = {glaze::KdlValue{tmpl.proxy_detour, {}}}});
                    }
                }
            }
        }
        for (auto& n : *tdoc) {
            if (n.name == "routing" || n.name == "dns" || n.name == "http-clients") {
                auto it = std::ranges::find(*cdoc, n.name, &glaze::KdlNode::name);
                if (it != cdoc->end()) *it = std::move(n);
                else cdoc->push_back(std::move(n));
            }
        }
        auto out = glaze::write_kdl(*cdoc);
        return out ? std::expected<std::string, std::string>(std::move(*out)) : std::unexpected("failed to serialize template overlay");
    }
}
