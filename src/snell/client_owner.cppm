export module snell.client_owner;
import std;
import crypto;
import snell.record;
import snell.kdf;
import snell.cipher;
import snell.client_start;
import snell.async_record;
import snell.owner;
import capy;
export namespace snell {
    class ClientOwner;
    template<class Socket> class ClientStream;
    // The token binds AEAD state to its original transport and credential
    // owner. A moved-from token is invalid and cannot start another request.
    template<class Socket> class ClientReuse {
        friend class ClientOwner;
        friend class ClientStream<Socket>;
        Socket* socket_;ClientOwner const* owner_;Record<Cipher> reader_,writer_;unsigned phase_=0;
        // Only completed streams should create this token; the records must
        // already be resumed and bound to the given owner and socket.
        ClientReuse(Socket& socket,ClientOwner const& owner,Record<Cipher> reader,Record<Cipher> writer)
            :socket_(&socket),owner_(&owner),reader_(std::move(reader)),writer_(std::move(writer)){}
    public:
        ClientReuse(ClientReuse const&)=delete;auto operator=(ClientReuse const&)->ClientReuse& =delete;
        ClientReuse(ClientReuse&& other) noexcept
            :socket_(std::exchange(other.socket_,nullptr)),owner_(other.owner_),reader_(std::move(other.reader_)),writer_(std::move(other.writer_)),phase_(other.phase_){}
        auto operator=(ClientReuse&& other) noexcept ->ClientReuse& {
            if(this!=&other){if(socket_)socket_->cancel();socket_=std::exchange(other.socket_,nullptr);owner_=other.owner_;
                reader_=std::move(other.reader_);writer_=std::move(other.writer_);phase_=other.phase_;}return *this;
        }
        ~ClientReuse(){if(socket_)socket_->cancel();}
        [[nodiscard]] auto can_resume(Socket const& socket,ClientOwner const& owner) const noexcept ->bool {
            return socket_==&socket&&owner_==&owner&&!phase_;
        }
    private:
        [[nodiscard]] auto claim(Socket& socket,ClientOwner const& owner)
          ->std::optional<std::pair<Record<Cipher>,Record<Cipher>>> {
            if(socket_!=&socket||owner_!=&owner||phase_!=2)return {};
            socket_=nullptr;return std::pair<Record<Cipher>,Record<Cipher>>(std::move(reader_),std::move(writer_));
        }
    };
    struct ClientConnected {
        Record<Cipher> reader,writer;Bytes early;
        ClientConnected(Record<Cipher> r,Record<Cipher> w,Bytes e):reader(std::move(r)),writer(std::move(w)),early(std::move(e)){}
        ClientConnected(ClientConnected&&)=default;auto operator=(ClientConnected&&)->ClientConnected& =default;
    };
    // Transport has already been dialed (possibly through detour). This owner
    // neither redials nor restarts the deadline; borrowed owner/socket must
    // outlive the task and connection tasks must drain before destruction.
    class ClientOwner {
        Credential credential_;
    public:
        explicit ClientOwner(Credential credential):credential_(std::move(credential)){}
        ClientOwner(ClientOwner const&)=delete;auto operator=(ClientOwner const&)->ClientOwner& =delete;
        // Split startup permits TCP callers to write application bytes before
        // awaiting a server that delays its acknowledgement until first data.
        template<class Socket> auto start(Socket& socket,Request request,View early,Deadline deadline) const
          ->capy::task<std::expected<Record<Cipher>,IoError>> {
            struct Clear {Request& request;~Clear(){crypto::cleanse(request.client_id);}} clear{request};
            if(!request.client_id.empty())co_return std::unexpected(IoError::state);
            if(auto user=credential_.user())request.client_id.assign(user->begin(),user->end());
            co_return co_await client_start(socket,credential_.psk(),request,early,deadline);
        }
        template<class Socket> auto reply(Socket& socket,Deadline deadline) const {return client_reply(socket,credential_.psk(),deadline);}
        // Continue the existing record sequence after both sides have sent an
        // authenticated EOF. The coroutine owns the token through completion
        // or abandonment, so suspended I/O cannot observe a moved token.
        template<class Socket> auto resume_start(Socket& socket,ClientReuse<Socket> reuse,Request request,Deadline deadline) const
          ->capy::task<std::expected<ClientReuse<Socket>,IoError>> {
            struct Clear {Request& request;~Clear(){crypto::cleanse(request.client_id);}} clear{request};
            if(reuse.socket_!=&socket||reuse.owner_!=this||reuse.phase_||!request.client_id.empty()||request.command!=5)co_return std::unexpected(IoError::state);
            reuse.phase_=1;
            struct Guard {Socket& socket;bool done=false;~Guard(){if(!done)socket.cancel();}} guard{socket};
            if(auto user=credential_.user())request.client_id.assign(user->begin(),user->end());
            auto plain=encode_request(request);if(!plain)co_return std::unexpected(IoError::record);
            struct ClearPlain {Bytes& bytes;~ClearPlain(){crypto::cleanse(bytes);}} clear_plain{*plain};
            auto result=co_await send_record(socket,reuse.writer_,*plain,{},deadline);if(!result)co_return std::unexpected(result.error());
            reuse.phase_=2;guard.done=true;co_return std::move(reuse);
        }
        template<class Socket> auto connect(Socket& socket,Request request,View early,Deadline deadline) const
          ->capy::task<std::expected<ClientConnected,ReplyError>> {
            if((request.command==1||request.command==5) && early.empty())co_return std::unexpected(ReplyError(IoError::state));
            struct Guard{Socket& socket;bool done=false;~Guard(){if(!done)socket.cancel();}} guard{socket};
            auto writer=co_await start(socket,std::move(request),early,deadline);
            if(!writer)co_return std::unexpected(ReplyError(writer.error()));
            auto reply=co_await client_reply(socket,credential_.psk(),deadline);
            if(!reply)co_return std::unexpected(reply.error());
            guard.done=true;
            co_return ClientConnected(std::move(reply->reader),std::move(*writer),std::move(reply->early));
        }
    };
    // The returned stream and borrowed owner/transport share one executor.
    // One reader and serialized writers; cancel then drain before destruction.
    template<class Socket> class ClientStream {
        Socket& socket_;ClientOwner const& owner_;Record<Cipher> writer_;std::optional<Record<Cipher>> reader_;
        capy::async_mutex write_lock_;Bytes cache_;std::size_t offset_=0,writers_=0;bool active_=true,reading_=false,input_eof_=false,output_eof_=false,reused_reply_=false;
        std::optional<ReplyError> reply_error_;
    public:
        ClientStream(Socket& socket,ClientOwner const& owner,Record<Cipher> writer):socket_(socket),owner_(owner),writer_(std::move(writer)){}
    private:
        ClientStream(Socket& socket,ClientOwner const& owner,Record<Cipher> reader,Record<Cipher> writer)
            :socket_(socket),owner_(owner),writer_(std::move(writer)),reader_(std::move(reader)),reused_reply_(true){}
    public:
        // A successful resume_start must precede consuming this token.
        static auto resume(Socket& socket,ClientOwner const& owner,ClientReuse<Socket>&& reuse) ->std::unique_ptr<ClientStream> {
            auto records=reuse.claim(socket,owner);if(!records)return {};
            try{return std::unique_ptr<ClientStream>(new ClientStream(socket,owner,std::move(records->first),std::move(records->second)));}
            catch(...){socket.cancel();throw;}
        }
        ClientStream(ClientStream const&)=delete;auto operator=(ClientStream const&)->ClientStream& =delete;
        auto cancel() noexcept ->void {if(active_){active_=false;socket_.cancel();}}
        [[nodiscard]] auto finish() ->std::optional<ClientReuse<Socket>> {
            if(!active_||reading_||writers_||!reader_||reused_reply_||!input_eof_||!output_eof_||offset_!=cache_.size())return {};
            if(!reader_->resume()||!writer_.resume()){cancel();return {};}
            active_=false;return ClientReuse<Socket>(socket_,owner_,std::move(*reader_),std::move(writer_));
        }
        [[nodiscard]] auto reply_error() const noexcept ->std::optional<ReplyError> const& {return reply_error_;}
        auto send(View bytes,Deadline deadline)->capy::task<bool> {
            ++writers_;struct Waiting{ClientStream& s;~Waiting(){--s.writers_;}} waiting{*this};
            auto [ec,lock]=co_await write_lock_.scoped_lock();if(ec||!active_||output_eof_)co_return false;
            struct Guard{ClientStream& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{*this};
            while(!bytes.empty()){auto part=bytes.first(std::min(bytes.size(),max_payload));if(!co_await send_record(socket_,writer_,part,{},deadline))co_return false;bytes=bytes.subspan(part.size());}
            guard.done=true;co_return true;
        }
        auto close_output(Deadline deadline)->capy::task<bool> {
            ++writers_;struct Waiting{ClientStream& s;~Waiting(){--s.writers_;}} waiting{*this};
            auto [ec,lock]=co_await write_lock_.scoped_lock();if(ec||!active_||output_eof_)co_return false;
            struct Guard{ClientStream& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{*this};
            if(!co_await send_record(socket_,writer_,{}, {},deadline))co_return false;output_eof_=true;guard.done=true;co_return true;
        }
        auto read(std::span<std::uint8_t> output,Deadline deadline)->capy::task<std::expected<std::size_t,IoError>> {
            if(!active_||reading_||output.empty())co_return std::unexpected(IoError::state);
            reading_=true;struct Guard{ClientStream& s;bool done=false;~Guard(){s.reading_=false;if(!done)s.cancel();}} guard{*this};
            if(!reader_){auto response=co_await owner_.reply(socket_,deadline);if(!response){reply_error_=std::move(response.error());co_return std::unexpected(IoError::record);}
                reader_.emplace(std::move(response->reader));cache_=std::move(response->early);offset_=0;}
            else if(reused_reply_){auto response=co_await receive_record(socket_,*reader_,deadline);
                if(!response||response->empty())co_return std::unexpected(response?IoError::record:response.error());
                if((*response)[0]==2){if(response->size()>=3&&response->size()==3+std::size_t((*response)[2]))
                    reply_error_=RemoteError{(*response)[1],std::string(response->begin()+3,response->end())};co_return std::unexpected(IoError::record);}
                if((*response)[0]!=0)co_return std::unexpected(IoError::record);
                cache_.assign(response->begin()+1,response->end());offset_=0;reused_reply_=false;}
            if(offset_==cache_.size()&&!input_eof_){auto next=co_await receive_record(socket_,*reader_,deadline);if(!next)co_return std::unexpected(next.error());cache_=std::move(*next);offset_=0;if(cache_.empty())input_eof_=true;}
            if(input_eof_){guard.done=true;co_return 0;}
            auto n=std::min(output.size(),cache_.size()-offset_);std::ranges::copy(std::span(cache_).subspan(offset_,n),output.begin());offset_+=n;guard.done=true;co_return n;
        }
    };
}
