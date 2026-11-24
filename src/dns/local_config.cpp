module dns.local_config;
import std;
import platform.ip_address;
import platform.platform_defaults;
import dns.message;

namespace dns {
    namespace {
        constexpr std::size_t max_file=1024*1024, max_records=4096;
        auto fields(std::string_view line) -> std::expected<std::vector<std::string_view>,LocalConfigError> {
            if (auto comment=line.find_first_of("#;"); comment!=line.npos) line=line.substr(0,comment);
            std::vector<std::string_view> out;
            while (!line.empty()) {
                auto start=line.find_first_not_of(" \t\r"); if (start==line.npos) break;
                line.remove_prefix(start); auto end=line.find_first_of(" \t\r");
                if (out.size()==max_records+1) return std::unexpected(LocalConfigError::too_many_records);
                out.push_back(line.substr(0,end));
                if (end==line.npos) break; line.remove_prefix(end);
            }
            return out;
        }
        auto lines(std::string_view text, auto&& fn) -> std::expected<void,LocalConfigError> {
            if (text.size()>max_file) return std::unexpected(LocalConfigError::too_large);
            while (!text.empty()) {
                auto end=text.find('\n'); auto items=fields(text.substr(0,end));
                if (!items) return std::unexpected(items.error());
                if (!items->empty()) { auto result=fn(*items); if (!result) return result; }
                if (end==text.npos) break; text.remove_prefix(end+1);
            }
            return {};
        }
        auto address(std::string_view input) -> std::optional<LocalServer> {
            auto parsed=platform::parse_ip_address(input);
            if (!parsed) return {};
            LocalServer result;
            result.address=parsed->bytes;
            result.ipv6=parsed->size==16;
            return result;
        }
        auto name(std::string_view input) -> std::optional<std::string> {
            auto query=make_query(0,{std::string(input),1}); if (!query) return {};
            std::string out;
            for (std::size_t pos=12; (*query)[pos];) {
                auto size=(*query)[pos++]; if (!out.empty()) out+='.';
                out.append(reinterpret_cast<char const*>(query->data()+pos),size); pos+=size;
            }
            if (out.empty()) return {}; return out;
        }
        auto number(std::string_view value, std::uint32_t max) -> std::optional<std::uint32_t> {
            std::uint32_t result=0; auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),result);
            if (ec!=std::errc{} || end!=value.data()+value.size() || !result || result>max) return {};
            return result;
        }
    }
    auto is_usable_system_dns_server(LocalServer const& server) noexcept -> bool {
        return !(server.ipv6 && platform::is_windows_site_local_fake_dns(server.address));
    }
    auto parse_local_address(std::string_view input) -> std::optional<LocalServer> { return address(input); }
    auto normalize_local_name(std::string_view input) -> std::optional<std::string> { return name(input); }
    auto local_search_candidates(LocalConfig const& config,std::string_view input,
        std::string const& normalized) -> std::vector<std::string> {
        if (input.ends_with('.')) return {normalized};
        std::vector<std::string> candidates;
        auto add=[&](std::string name) {
            if (!std::ranges::contains(candidates,name)) candidates.push_back(std::move(name));
        };
        if (std::ranges::count(normalized,'.')>=config.ndots) add(normalized);
        for (auto const& suffix:config.search) {
            if (suffix.empty()) add(normalized);
            else if (auto name=normalize_local_name(normalized+"."+suffix)) add(std::move(*name));
        }
        add(normalized);
        return candidates;
    }
    auto parse_local_resolv(std::string_view input) -> std::expected<LocalConfig,LocalConfigError> {
        LocalConfig config;
        auto parsed=lines(input,[&](auto const& items) -> std::expected<void,LocalConfigError> {
            if (items[0]=="nameserver" && items.size()>1 && config.servers.size()<3) {
                auto parsed=address(items[1]); if (!parsed) return std::unexpected(LocalConfigError::invalid_address);
                if (is_usable_system_dns_server(*parsed)) config.servers.push_back(*parsed);
            } else if ((items[0]=="search" || items[0]=="domain") && items.size()>1) {
                std::vector<std::string> search;
                auto end=items[0]=="domain" ? std::size_t{2} : items.size();
                if (end>7) return std::unexpected(LocalConfigError::too_many_records);
                for (std::size_t i=1;i<end;++i) {
                    if (items[i]==".") { search.emplace_back(); continue; }
                    auto parsed=name(items[i]); if (!parsed) return std::unexpected(LocalConfigError::invalid_name); search.push_back(std::move(*parsed));
                }
                config.search=std::move(search);
            } else if (items[0]=="options") {
                for (auto item:std::span(items).subspan(1)) {
                    if (item.starts_with("timeout:")) { auto value=number(item.substr(8),30); if (!value) return std::unexpected(LocalConfigError::invalid_option); config.timeout_seconds=*value; }
                    else if (item.starts_with("attempts:")) { auto value=number(item.substr(9),5); if (!value) return std::unexpected(LocalConfigError::invalid_option); config.attempts=*value; }
                    else if (item.starts_with("ndots:")) {
                        auto value=item.substr(6); std::uint32_t parsed=0;
                        auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),parsed);
                        if (value.empty() || ec!=std::errc{} || end!=value.data()+value.size()) return std::unexpected(LocalConfigError::invalid_option);
                        config.ndots=std::min(parsed,15u);
                    }
                    else if (item=="rotate") config.rotate=true;
                    else if (item=="use-vc" || item=="usevc" || item=="tcp") config.use_tcp=true;
                }
            }
            return {};
        });
        if (!parsed) return std::unexpected(parsed.error());
        if (config.servers.empty()) return std::unexpected(LocalConfigError::no_servers);
        return config;
    }
    auto parse_local_hosts(std::string_view input) -> std::expected<std::vector<LocalHost>,LocalConfigError> {
        std::vector<LocalHost> result;
        auto parsed=lines(input,[&](auto const& items) -> std::expected<void,LocalConfigError> {
            if (items.size()<2) return {};
            auto ip=address(items[0]); if (!ip) return std::unexpected(LocalConfigError::invalid_address);
            for (auto item:std::span(items).subspan(1)) {
                auto host=name(item); if (!host) return std::unexpected(LocalConfigError::invalid_name);
                if (result.size()==max_records) return std::unexpected(LocalConfigError::too_many_records);
                result.push_back({std::move(*host),*ip});
            }
            return {};
        });
        if (!parsed) return std::unexpected(parsed.error()); return result;
    }
    auto load_local_snapshot(std::string_view resolv_path, std::string_view hosts_path) -> std::expected<LocalSnapshot,LocalConfigError> {
        auto resolv=detail::read_local_config_file(resolv_path,max_file); if (!resolv) return std::unexpected(resolv.error());
        auto hosts=detail::read_local_config_file(hosts_path,max_file); if (!hosts) return std::unexpected(hosts.error());
        auto config=parse_local_resolv(*resolv); if (!config) return std::unexpected(config.error());
        auto entries=parse_local_hosts(*hosts); if (!entries) return std::unexpected(entries.error());
        return LocalSnapshot{std::move(*config),std::move(*entries)};
    }
    LocalSnapshotSource::LocalSnapshotSource(std::string resolv_path,std::string hosts_path,std::chrono::milliseconds interval,bool eager)
        : resolv_path_(std::move(resolv_path)),hosts_path_(std::move(hosts_path)),interval_(std::max(interval,std::chrono::milliseconds(10))),
          current_(std::make_shared<LocalSnapshot const>()),eager_(eager) {
        if (eager_) ensure_started();
    }
    LocalSnapshotSource::~LocalSnapshotSource() { stop(); }
    auto LocalSnapshotSource::ensure_started() const noexcept -> void {
        if (started_.load(std::memory_order_acquire) || stopped_.load(std::memory_order_acquire)) return;
        std::lock_guard lock(mutex_);
        if (active_ || stopped_.load(std::memory_order_acquire)) return;
        stop_ = std::stop_source{};
        active_ = true;
        if (eager_) refresh();
        try {
            auto token = stop_.get_token();
            thread_ = std::jthread([this, token, initial_refresh = !eager_]() {
                if (initial_refresh && !token.stop_requested()) refresh();
                std::unique_lock lk(mutex_);
                while (!token.stop_requested()) {
                    wake_.wait_for(lk, token, interval_, [] { return false; });
                    if (token.stop_requested()) break;
                    lk.unlock(); refresh(); lk.lock();
                }
            });
            started_.store(true, std::memory_order_release);
        } catch (...) {
            active_ = false;
        }
    }
    auto LocalSnapshotSource::stop() noexcept -> void {
        std::jthread joined;
        {
            std::lock_guard lock(mutex_);
            stopped_.store(true, std::memory_order_release);
            if (!active_ && !thread_.joinable()) return;
            active_ = false;
            stop_.request_stop();
            joined = std::move(thread_);
        }
        wake_.notify_all();
        if (joined.joinable()) joined.join();
    }
    auto LocalSnapshotSource::refresh() const noexcept -> void {
        try {
            auto loaded=load_local_snapshot(resolv_path_,hosts_path_);
            LocalSnapshot next=loaded ? std::move(*loaded) : LocalSnapshot{};
            auto current=current_.load(std::memory_order_acquire);
            if (!current || *current!=next) current_.store(std::make_shared<LocalSnapshot const>(std::move(next)),std::memory_order_release);
        } catch (...) {
            // A read or allocation failure must not silently preserve stale DNS.
            current_.store({},std::memory_order_release);
        }
    }
    auto LocalSnapshotSource::acquire() const noexcept -> std::shared_ptr<LocalSnapshot const> {
        if (!started_.load(std::memory_order_acquire) && !stopped_.load(std::memory_order_acquire))
            ensure_started();
        return current_.load(std::memory_order_acquire);
    }
    namespace {
        auto snapshot_slot(bool create) noexcept -> LocalSnapshotSource* {
            static std::atomic<bool> created{false};
            if (!create && !created.load(std::memory_order_acquire)) return nullptr;
            static LocalSnapshotSource source("/etc/resolv.conf","/etc/hosts",std::chrono::seconds(1),true);
            created.store(true, std::memory_order_release);
            return &source;
        }
    }
    auto system_local_snapshots() -> LocalSnapshotSource& {
        return *snapshot_slot(true);
    }
    auto stop_system_local_snapshots() noexcept -> void {
        if (auto* source = snapshot_slot(false)) source->stop();
    }
}
