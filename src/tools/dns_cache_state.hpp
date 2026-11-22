// Private state for numeric DNS message listener views.
#pragma once
namespace cli {
    class DnsCacheState {
        static constexpr auto filename="messages.cache";
        static constexpr auto staging=".messages.next";
        static constexpr std::string_view legacy_magic="NXDNS1";
        static constexpr std::string_view magic="NXDNS2";
        static constexpr std::size_t max_bytes=1024*1024;
        using Endpoint=nex::corosio::endpoint;

        struct File {
            int fd;
            explicit File(int value) noexcept : fd(value) {}
            File(File const&)=delete;
            auto operator=(File const&) -> File& = delete;
            ~File() { if (fd>=0) ::close(fd); }
            auto close(this File& self) noexcept -> bool { return ::close(std::exchange(self.fd,-1))==0; }
        };

        File directory_;
        explicit DnsCacheState(int directory) noexcept : directory_(directory) {}

        static auto wall_seconds() noexcept -> std::uint64_t {
            return static_cast<std::uint64_t>(std::chrono::floor<std::chrono::seconds>(
                std::chrono::system_clock::now()).time_since_epoch().count());
        }

        static auto append(std::string& out,std::uint64_t value,unsigned width) -> void {
            for (unsigned i=width;i>0;--i) out.push_back(static_cast<char>(value>>((i-1)*8)));
        }

        static auto take(std::string_view& input,unsigned width) noexcept -> std::uint64_t {
            std::uint64_t value=0;
            for (unsigned i=0;i<width;++i)
                value=(value<<8)|static_cast<unsigned char>(input[i]);
            input.remove_prefix(width);
            return value;
        }

        static auto checksum(std::string_view bytes) noexcept -> std::uint64_t {
            std::uint64_t value=14695981039346656037ull;
            for (unsigned char byte:bytes) value=(value^byte)*1099511628211ull;
            return value;
        }

        static auto legacy_identity(Endpoint const& endpoint,bool tcp) -> std::string {
            auto address=endpoint.address();
            std::string result(legacy_magic);
            result.push_back(address.is_v6() ? 6 : 4);
            result.push_back(tcp ? 1 : 0);
            append(result,endpoint.port(),2);
            if (address.is_v6()) {
                auto bytes=address.to_v6().to_bytes();
                result.append(reinterpret_cast<char const*>(bytes.data()),bytes.size());
            } else {
                auto bytes=address.to_v4().to_bytes();
                result.append(reinterpret_cast<char const*>(bytes.data()),bytes.size());
            }
            return result;
        }

        auto read(this DnsCacheState const& self) -> std::expected<std::string,std::string> {
            File file(::openat(self.directory_.fd,filename,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
            if (file.fd<0) {
                if (errno==ENOENT) return std::string{};
                return std::unexpected("cannot open snapshot");
            }
            struct stat info{};
            if (::fstat(file.fd,&info)<0 || !S_ISREG(info.st_mode) || info.st_uid!=::geteuid() ||
                info.st_nlink!=1 || (info.st_mode&07777)!=0600)
                return std::unexpected("snapshot must be a private regular file");
            std::string wire;
            std::array<char,8192> chunk;
            for (;;) {
                auto count=::read(file.fd,chunk.data(),chunk.size());
                if (count<0 && errno==EINTR) continue;
                if (count<0) return std::unexpected("cannot read snapshot");
                if (count==0) return wire;
                if (static_cast<std::size_t>(count)>max_bytes-wire.size())
                    return std::unexpected("snapshot exceeds byte limit");
                wire.append(chunk.data(),static_cast<std::size_t>(count));
            }
        }

        auto write(this DnsCacheState const& self,std::string_view bytes) -> std::expected<void,std::string> {
            auto directory=self.directory_.fd;
            if (::unlinkat(directory,staging,0)<0 && errno!=ENOENT)
                return std::unexpected("cannot remove stale checkpoint");
            File file(::openat(directory,staging,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
            if (file.fd<0) return std::unexpected("cannot open checkpoint");
            while (!bytes.empty()) {
                auto count=::write(file.fd,bytes.data(),bytes.size());
                if (count<0 && errno==EINTR) continue;
                if (count<=0) break;
                bytes.remove_prefix(static_cast<std::size_t>(count));
            }
            auto ready=bytes.empty() && ::fchmod(file.fd,0600)==0 && ::fsync(file.fd)==0;
            auto closed=file.close();
            if (!ready || !closed || ::renameat(directory,staging,directory,filename)<0) {
                (void)::unlinkat(directory,staging,0);
                return std::unexpected("cannot publish checkpoint");
            }
            if (::fsync(directory)<0) return std::unexpected("checkpoint directory sync failed");
            return {};
        }

    public:
        struct Scope {
            std::string identity, legacy;
            std::vector<dns::MessageCache::View> views;

            Scope(config::DnsRouting const& routing,std::span<dns::MessageUpstream const> upstreams)
                :identity(magic) {
                append(identity,routing.message_cache_policy.size(),4);
                identity+=routing.message_cache_policy;
                if (!routing.cache_rule_fingerprints.empty()) {
                    append(identity,routing.cache_rule_fingerprints.size(),4);
                    identity+=routing.cache_rule_fingerprints;
                }
                views.reserve(upstreams.size());
                for (std::size_t index=0;index<upstreams.size();++index) {
                    auto const& upstream=upstreams[index];
                    auto const& entry=routing.servers[index].upstream;
                    append(identity,entry ? entry->binding.routing_mark.value_or(0) : 0,4);
                    views.emplace_back(index,upstream.endpoint,upstream.tcp,nullptr);
                }
                if (routing.rules.empty() && upstreams.size()==1 && routing.servers.front().upstream &&
                    !routing.servers.front().upstream->tls && !routing.servers.front().upstream->binding.configured())
                    legacy=legacy_identity(upstreams.front().endpoint,upstreams.front().tcp);
            }
        };

        static auto open(std::string const& path) -> std::expected<std::shared_ptr<DnsCacheState>,std::string> {
            File handle(::open(path.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
            auto directory=handle.fd;
            struct stat info{};
            if (directory<0 || ::fstat(directory,&info)<0 || info.st_uid!=::geteuid() || (info.st_mode&077)!=0)
                return std::unexpected("DNS message cache directory must be owned by the process user and private");
            if (::flock(directory,LOCK_EX|LOCK_NB)<0)
                return std::unexpected("DNS message cache directory cannot be locked");
            return std::shared_ptr<DnsCacheState>(new DnsCacheState(std::exchange(handle.fd,-1)));
        }

        auto restore(this DnsCacheState const& self,dns::MessageCache& cache,Scope const& scope)
            -> std::expected<void,std::string> {
            auto file=self.read();
            if (!file) return std::unexpected(std::move(file.error()));
            if (file->empty()) return {};
            std::string_view input=*file;
            bool old=!scope.legacy.empty() && input.starts_with(scope.legacy);
            auto const& expected=old ? scope.legacy : scope.identity;
            if (!input.starts_with(expected)) return std::unexpected("snapshot DNS policy, upstream or format changed");
            if (input.size()<expected.size()+18) return std::unexpected("snapshot header is incomplete");
            auto footer=input.substr(input.size()-8);
            input.remove_suffix(8);
            if (checksum(input)!=take(footer,8)) return std::unexpected("snapshot checksum mismatch");
            input.remove_prefix(expected.size());
            auto saved=take(input,8), now=wall_seconds();
            if (now<saved) return std::unexpected("snapshot timestamp is in the future");
            auto elapsed=static_cast<std::uint32_t>(std::min<std::uint64_t>(now-saved,600)+1);
            auto rows=take(input,2);
            if (rows>256) return std::unexpected("snapshot exceeds entry limit");
            auto steady=std::chrono::steady_clock::now();
            auto invalid=[&]() -> std::expected<void,std::string> {
                cache.clear();
                return std::unexpected("snapshot contains invalid entries");
            };
            for (std::size_t row=0;row<rows;++row) {
                if (input.size()<(old ? 6u : 8u)) return invalid();
                auto upstream=old ? 0 : take(input,2);
                auto query=take(input,2), answer=take(input,2), ttl=take(input,2);
                if (upstream>=scope.views.size() || !query || !answer || !ttl || ttl>600 ||
                    query+answer>input.size()) return invalid();
                auto bytes=reinterpret_cast<std::uint8_t const*>(input.data());
                if (!cache.restore(scope.views[upstream],{bytes,static_cast<std::size_t>(query)},
                    std::vector<std::uint8_t>(bytes+query,bytes+query+answer),
                    static_cast<std::uint32_t>(ttl),elapsed,steady))
                    return invalid();
                input.remove_prefix(query+answer);
            }
            return input.empty() ? std::expected<void,std::string>{} : invalid();
        }

        auto save(this DnsCacheState const& self,dns::MessageCache const& cache,Scope const& scope)
            -> std::expected<void,std::string> {
            if (scope.identity.size()>max_bytes-18) return std::unexpected("DNS policy exceeds snapshot byte limit");
            auto wire=scope.identity;
            append(wire,wall_seconds(),8);
            auto count_at=wire.size();
            append(wire,0,2);
            unsigned count=0;
            auto entries=cache.checkpoint(scope.views,std::chrono::steady_clock::now(),max_bytes-wire.size()-8);
            for (auto const& row:entries) {
                append(wire,row.view.upstream,2);
                append(wire,row.query.size(),2);
                append(wire,row.response.size(),2);
                append(wire,row.remaining,2);
                wire.append(reinterpret_cast<char const*>(row.query.data()),row.query.size());
                wire.append(reinterpret_cast<char const*>(row.response.data()),row.response.size());
                ++count;
            }
            wire[count_at]=static_cast<char>(count>>8);
            wire[count_at+1]=static_cast<char>(count);
            append(wire,checksum(wire),8);
            return self.write(wire);
        }
    };
}
