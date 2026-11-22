// Private to the proxy DNS implementation.
        // A response query owns its cancellation registration independently
        // of the enclosing session; a future concurrent owner can hold one
        // instance per evaluate without sharing a mutable resolver pointer.
        class ResponseOperation {
            Session& session_;
            nex::corosio::io_context& context_;
            std::size_t selected_;
            std::string name_;
            std::uint16_t type_;
            Clock::time_point deadline_;
            std::shared_ptr<dns::LocalSnapshot const> snapshot_;
            bool disabled_,canceled_=false,started_=false;
            std::size_t* rotation_;
            std::optional<std::string> candidate_;
            std::optional<dns::ClientSubnet> subnet_;
            void* active_=nullptr;
            void (*cancel_active_)(void*) noexcept=nullptr;
        public:
            ResponseOperation(Session& session,nex::corosio::io_context& context,std::size_t selected,
                std::string const& name,std::uint16_t type,Clock::time_point deadline,LocalSnapshotRef snapshot,
                bool disabled,std::size_t* rotation,std::optional<std::string_view> candidate,std::optional<dns::ClientSubnet> subnet)
                :session_(session),context_(context),selected_(selected),name_(name),type_(type),deadline_(deadline),
                 snapshot_(snapshot ? *snapshot : nullptr),disabled_(disabled),rotation_(rotation),
                 candidate_(candidate ? std::optional<std::string>(*candidate) : std::nullopt),subnet_(subnet) {}
            ResponseOperation(ResponseOperation const&)=delete;
            auto operator=(ResponseOperation const&) -> ResponseOperation& = delete;
            auto cancel() noexcept -> void {canceled_=true;if(cancel_active_)cancel_active_(active_);}
            auto run() -> nex::capy::task<std::expected<RawSelection,dns::detail::ResolveError>> {
                if(std::exchange(started_,true))co_return std::unexpected(dns::detail::ResolveError::state);
                if(canceled_ || session_.closed)co_return std::unexpected(dns::detail::ResolveError::canceled);
                auto candidate=candidate_ ? std::optional<std::string_view>(*candidate_) : std::nullopt;
                co_return co_await response_server(session_,context_,selected_,name_,type_,deadline_,snapshot_ ? &snapshot_ : nullptr,
                    disabled_,active_,cancel_active_,canceled_,rotation_,candidate,subnet_);
            }
        };
