// Shared by native UDP generations on the command's serialized control thread.
#pragma once
    class UdpIdentitySecret {
        std::vector<std::uint8_t> key_;
    public:
        explicit UdpIdentitySecret(std::span<std::uint8_t const> key) : key_(key.begin(),key.end()) {}
        ~UdpIdentitySecret() {crypto::cleanse(key_);}
        UdpIdentitySecret(UdpIdentitySecret const&)=delete;
        auto operator=(UdpIdentitySecret const&) -> UdpIdentitySecret& = delete;
        [[nodiscard]] auto decode(std::span<std::uint8_t const> packet) const noexcept -> std::optional<UdpIdentity> {
            return open_udp_identity(key_,packet);
        }
    };
    struct UdpIdentityRoute {
        std::shared_ptr<UdpIdentitySecret const> secret;
        IdentityBlock hash;
        std::string user;
        proxy::PrincipalBudget const* principal=nullptr;
    };

    class UdpListenerIngress {
        struct Key {
            std::vector<std::uint8_t> bytes;
            CipherMethod method=CipherMethod::aes;
            std::shared_ptr<UdpServerSessions> sessions;
            ~Key() {crypto::cleanse(bytes);}
        };
        struct Binding {
            udp_io::endpoint endpoint;
            std::uint64_t generation;
            int fd;
            void* owner;
            std::size_t index;
            UdpIdentityRoute const* identity;
            bool (*receive)(void*,std::size_t,std::span<std::uint8_t const>,UdpPeer,bool,std::optional<UdpRequestIdentity>);
            void (*cancel)(void*,std::size_t) noexcept;
        };
        std::vector<std::unique_ptr<Key>> keys_;
        std::vector<Binding> bindings_;
        std::uint64_t generation_=0;
    public:
        [[nodiscard]] auto generation() const noexcept -> std::uint64_t {return generation_;}

        struct Datagram {UdpPeer source;std::size_t size;};

        // Each executor wait only observes readiness. Taking the datagram on
        // the control thread after checking cancellation avoids an old
        // submitted receive consuming from the transferred queue.
        [[nodiscard]] static auto read(int fd,std::span<std::uint8_t> buffer)
            -> std::expected<std::optional<Datagram>,std::error_code> {
            sockaddr_storage from{};
            socklen_t width=sizeof(from);
            auto count=::recvfrom(fd,buffer.data(),buffer.size(),MSG_DONTWAIT|MSG_TRUNC,
                reinterpret_cast<sockaddr*>(&from),&width);
            if (count<0) {
                if (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR) return std::nullopt;
                return std::unexpected(std::error_code(errno,std::generic_category()));
            }
            if (static_cast<std::size_t>(count)>buffer.size()) return std::nullopt;
            UdpPeer source{};
            if (from.ss_family==AF_INET && width>=sizeof(sockaddr_in)) {
                auto const& address=reinterpret_cast<sockaddr_in const&>(from);
                source.family=4;
                source.port=ntohs(address.sin_port);
                std::memcpy(source.address.data(),&address.sin_addr,4);
            } else if (from.ss_family==AF_INET6 && width>=sizeof(sockaddr_in6)) {
                auto const& address=reinterpret_cast<sockaddr_in6 const&>(from);
                if (address.sin6_scope_id) return std::nullopt;
                source.family=6;
                source.port=ntohs(address.sin6_port);
                std::memcpy(source.address.data(),&address.sin6_addr,16);
            } else return std::nullopt;
            return Datagram{source,static_cast<std::size_t>(count)};
        }

        [[nodiscard]] auto replay(std::span<std::uint8_t const> key,std::size_t capacity,CipherMethod method=CipherMethod::aes)
            -> std::shared_ptr<UdpServerSessions> {
            std::erase_if(keys_,[](auto const& item) {
                return item->sessions.use_count()==1 && !item->sessions->has_history();
            });
            auto previous=std::ranges::find_if(keys_,[key,method](auto const& item) {
                return item->method==method && crypto::constant_time_equal(item->bytes,key);
            });
            if (previous!=keys_.end()) return (*previous)->sessions;
            if (keys_.size()>=64) return {};
            auto state=std::make_unique<Key>();
            state->bytes.assign(key.begin(),key.end());
            state->method=method;
            state->sessions=std::make_shared<UdpServerSessions>(capacity,false,method);
            auto sessions=state->sessions;
            keys_.push_back(std::move(state));
            return sessions;
        }

        struct Socket {int fd=-1;bool receive=true;};
        [[nodiscard]] auto duplicate(udp_io::endpoint endpoint,std::uint64_t next,bool share)
            -> std::expected<Socket,std::error_code> {
            for (auto const& binding : bindings_ | std::views::reverse) {
                if (binding.generation>next || binding.endpoint!=endpoint ||
                    (binding.generation==next && (!share || !binding.identity))) continue;
                auto fd=::fcntl(binding.fd,F_DUPFD_CLOEXEC,0);
                if (fd<0) return std::unexpected(std::error_code(errno,std::generic_category()));
                return Socket{fd,binding.generation<next};
            }
            return Socket{};
        }

        auto add(udp_io::endpoint endpoint,std::uint64_t generation,int fd,void* owner,std::size_t index,
            UdpIdentityRoute const* identity,
            bool (*receive)(void*,std::size_t,std::span<std::uint8_t const>,UdpPeer,bool,std::optional<UdpRequestIdentity>),
            void (*cancel)(void*,std::size_t) noexcept) -> void {
            bindings_.push_back({endpoint,generation,fd,owner,index,identity,receive,cancel});
        }

        auto remove(void* owner) noexcept -> void {
            std::erase_if(bindings_,[owner](auto const& item) {return item.owner==owner;});
        }

        auto publish(std::uint64_t next) noexcept -> void {
            generation_=next;
            for (auto const& active : bindings_) {
                if (active.generation!=next) continue;
                for (auto const& previous : bindings_) {
                    if (previous.generation<next && previous.endpoint==active.endpoint)
                        previous.cancel(previous.owner,previous.index);
                }
            }
        }

        auto route(udp_io::endpoint endpoint,std::uint64_t receiving,std::span<std::uint8_t const> packet,UdpPeer source)
            -> void {
            // The newest receive task owns the kernel queue. Its policy
            // tries first; retired owners may only process known sessions.
            UdpIdentitySecret const* last_secret=nullptr;
            std::optional<UdpIdentity> decoded;
            for (auto const& binding : bindings_ | std::views::reverse) {
                if (binding.generation>receiving || binding.endpoint!=endpoint) continue;
                std::optional<UdpRequestIdentity> user;
                auto wire=packet;
                if (binding.identity) {
                    auto const& route=*binding.identity;
                    if (last_secret!=route.secret.get()) {
                        last_secret=route.secret.get();
                        decoded=last_secret->decode(packet);
                    }
                    if (!decoded || !crypto::constant_time_equal(decoded->user_hash,route.hash)) continue;
                    user=UdpRequestIdentity{decoded->header,route.user};
                    if (route.principal) {
                        user->principal=route.principal;
                        user->byte_budget=&route.principal->bytes();
                        user->acquire=[](void const* owner) -> std::shared_ptr<void> {
                            auto const& budget=*static_cast<proxy::PrincipalBudget const*>(owner);
                            auto lease=budget.acquire(proxy::PrincipalResource::connection);
                            if (!lease) return {};
                            return std::make_shared<proxy::SessionQuota::Lease>(std::move(*lease));
                        };
                    }
                    wire=packet.subspan(32);
                }
                if (binding.receive(binding.owner,binding.index,wire,source,binding.generation==generation_,user))
                    return;
            }
        }
    };
