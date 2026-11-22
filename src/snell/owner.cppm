export module snell.owner;
import std;
import crypto;
import snell.record;
import snell.replay;
import snell.server_start;
import snell.async_record;
import nexus.thirdparty.capy;
export namespace snell {
    enum class CredentialError { missing_psk,userkey_too_long };
    // Parsed file bytes are consumed, never copied to diagnostics. A null
    // user key permits single-PSK mode; a present key must match exactly.
    class Credential {
        Bytes psk_;std::optional<Bytes> user_;
        Credential(Bytes psk,std::optional<Bytes> user):psk_(std::move(psk)),user_(std::move(user)){}
        auto clear() noexcept ->void {crypto::cleanse(psk_);if(user_)crypto::cleanse(*user_);}
    public:
        ~Credential(){clear();}Credential(Credential const&)=delete;auto operator=(Credential const&)->Credential& =delete;
        Credential(Credential&&)=default;auto operator=(Credential&& other) noexcept ->Credential& {if(this!=&other){clear();psk_=std::move(other.psk_);user_=std::move(other.user_);}return *this;}
        [[nodiscard]] static auto create(Bytes psk,std::optional<Bytes> user)->std::expected<Credential,CredentialError> {
            if(psk.empty() || (user && user->size()>255)) {crypto::cleanse(psk);if(user)crypto::cleanse(*user);return std::unexpected(psk.empty()?CredentialError::missing_psk:CredentialError::userkey_too_long);}
            return Credential(std::move(psk),std::move(user));
        }
        [[nodiscard]] auto psk() const noexcept ->View{return psk_;}
        [[nodiscard]] auto user() const noexcept ->std::optional<View>{if(!user_)return {};return View(*user_);}
        [[nodiscard]] auto accepts(Request const& request) const noexcept ->bool {return !user_ || crypto::constant_time_equal(*user_,request.client_id);}
    };
    // Shared across workers for one credential generation. Owner must outlive
    // every pending handshake; retirement waits for all streams to drain.
    template<std::size_t Capacity> class ServerOwner {
        Credential credential_;std::shared_ptr<ReplayCache<Capacity>> replay_;std::chrono::steady_clock::duration window_;
    public:
        ServerOwner(Credential credential,std::chrono::steady_clock::duration window,std::shared_ptr<ReplayCache<Capacity>> replay):credential_(std::move(credential)),replay_(std::move(replay)),window_(window){if(!replay_ || window<=std::chrono::steady_clock::duration::zero())throw std::invalid_argument("invalid Snell replay window");}
        ServerOwner(ServerOwner const&)=delete;auto operator=(ServerOwner const&)->ServerOwner& =delete;
        template<class Socket> auto start(Socket& socket,Deadline deadline)->nex::capy::task<std::expected<ServerStart,StartError>> {
            return server_start(socket,credential_.psk(),*replay_,window_,deadline,[this](Request const& request){return credential_.accepts(request);});
        }
        [[nodiscard]] auto psk() const noexcept ->View{return credential_.psk();}
        [[nodiscard]] auto accepts(Request const& request) const noexcept ->bool{return credential_.accepts(request);}
    };
}
