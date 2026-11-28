#include <csignal>
#include <sys/stat.h>

import std;
import platform.ip_address;
import state.ruleset_cache;
import state.file;
import state.core;
import config;
import cli.dns_transports;
import cli.route_files;
import cli.rule_fetch_response;
import crypto;
import http.connect;
import http.header;
import http.named_client;
import rulefile;
import rules.rule_input;
import cli.rule_fetch_url;
import cli.rule_fetch_alternative;
import cli.rule_watch_client;
import cli.rule_fetch_cache;
import cli.proxy_providers;
import provider;
import capy;
import corosio;

namespace {
    namespace capy = ::capy;
    namespace http=http;
    namespace fetch=cli::rule_fetch;
    using namespace cli::rule_fetch_detail;
}

static auto fetch_once(int argc,char** argv,WatchState* watch=nullptr) -> int {
    if(argc==2 && std::string_view(argv[1])=="--help") {
        std::cout << "usage: nexus rule fetch <config> <client> <https-url> <kdl|beve|srs|nxmm> <output> [--sha256 <hex>] [--cache-dir <dir>] [--ruleset-cache-max-bytes <bytes>] [--offline-cache]\n";
        return 0;
    }
    if(argc<6) {std::cerr << "use nexus rule fetch --help\n";return 2;}
    auto options=fetch_options(argc,argv);
    if (!options) {std::cerr << options.error() << '\n';return 2;}
    auto const& pin=options->pin;
    auto source=::rulefile::read_regular_file(argv[1]);
    if(!source) {std::cerr << source.error() << '\n';return 1;}
    auto config=config::parse_kdl(*source);
    if(!config) {std::cerr << config.error() << '\n';return 1;}
    auto cache_setup=configure_rule_cache(*options,*config);
    if (!cache_setup) {std::cerr << cache_setup.error() << '\n';return 1;}
    auto url=parse_url(argv[3]);
    auto name=std::string_view(argv[4]);
    using Format=::rules::InputFormat;
    std::optional<Format> format;
    if(name=="kdl")format=Format::kdl;
    if(name=="beve")format=Format::beve;
    if(name=="srs")format=Format::srs;
    if(name=="nxmm")format=Format::nxmm;
    if (!url || !format) {std::cerr << "invalid HTTPS URL or rule format\n";return 1;}
    std::optional<::state::RulesetKey> key;
    ::state::RulesetLookup cached{};
    if (options->cache) {
        if (std::ranges::any_of(std::array<std::filesystem::path,4>{argv[1],argv[5],config->selector_state_directory,
            config->dns && config->dns->fakeip ? config->dns->fakeip->state_directory : std::string{}},
            [&](auto const& path) { return cache_path_conflict(options->cache_root,path); })) {
            std::cerr << "rule cache overlaps configuration, destination or authoritative state\n";
            return 1;
        }
        key=cache_key(*url,*format,*source,argv[2]);
        if (!key) {std::cerr << "cannot construct rule cache key\n";return 1;}
        auto hit=options->cache->lookup(*key);
        if (!hit) return cache_error(hit.error());
        cached=std::move(*hit);
        if (cached.hit && !validate_download(cached.hit->body,*format,std::nullopt)) {
            auto discarded=options->cache->discard(*key,cached.clear_epoch,cached.hit->metadata.content_blake3);
            if (!discarded) return cache_error(discarded.error());
            cached.hit.reset();
        }
        if (cached.hit && pin && !::crypto::constant_time_equal(
            std::span(reinterpret_cast<std::uint8_t const*>(cached.hit->metadata.content_sha256.data()),pin->size()),*pin))
            cached.hit.reset();
    }
    if (watch && watch->config!=*source) {
        watch->client.reset();
        watch->config=std::move(*source);
        watch->alternative.reset();
        watch->validator.reset();
    }
    std::unique_ptr<http::NamedHttpClient> transient;
    auto& stored=watch ? watch->client : transient;
    auto dependencies=watch ? watch_dependencies(*config,argv[2]) : std::nullopt;
    if (watch && stored && dependencies!=watch->dependencies) {
        stored.reset();
        watch->alternative.reset();
    }
    if (!stored) {
        auto created=http::NamedHttpClient::create(std::move(*config),argv[2],url->authority);
        if (!created) {std::cerr << created.error() << '\n';return 1;}
        if (dependencies) {
            watch->dependencies=std::move(dependencies);
            stored=std::move(*created);
        } else transient=std::move(*created);
    }
    auto& client=stored ? *stored : *transient;
    auto& context=client.executor();
    auto const* selected=&client.settings();
    auto started=Clock::now();
    auto deadline=started+std::chrono::milliseconds(selected->timeout_ms);
    fetch::Result result=std::unexpected("HTTPS operation did not complete");
    std::vector<http::HeaderField> request_headers;
    bool manage_validator=(watch || options->cache) && std::ranges::none_of(selected->headers,[](auto const& field) {
        auto const& name=field.first;
        return name=="if-none-match" || name=="if-modified-since" || name=="if-match" ||
               name=="if-unmodified-since" || name=="if-range" || name=="range";
    });
    fetch::ResponsePolicy policy{.redirect=selected->max_redirects>0};
    auto automatic=watch && client.allows_http3_alternative();
    Advertisement advertisement;
    EntityTag validator;
    Location location;
    std::string last_modified;
    auto headers=[&](std::string_view name,std::string_view value) {
        if (manage_validator) validator.add(name,value);
        if (name=="last-modified" && value.size()<=128 && http::valid_header_field_value(value) &&
            std::ranges::none_of(value,[](unsigned char byte) {return byte<0x20 || byte==0x7f;})) last_modified=value;
        if (automatic) advertisement.add(name,value);
        if (policy.redirect) location.add(name,value);
    };
    std::optional<http::HttpHeaderConsumer> observe;
    if (manage_validator || automatic || policy.redirect) observe.emplace(headers);
    auto run=[&](Clock::time_point until,std::optional<std::uint16_t> alternative={}) {
        std::string data;
        auto consume=[&](std::string_view bytes,Clock::time_point) -> capy::task<bool> {
            data.append(bytes);
            co_return true;
        };
        auto operation=client.get({url->target,request_headers,until,alternative,started,policy.conditional,policy.redirect},
            consume,observe);
        bool done=false;
        std::stop_source stop;
        context.restart();
        result=std::unexpected("HTTPS operation did not complete");
        capy::run_async(context.get_executor(),stop.get_token(),[&](auto value) noexcept {
            if (value) result=fetch::Response{*value,std::move(data)};
            else result=std::unexpected(std::move(value.error()));
            done=true;
        },[&](std::exception_ptr) noexcept {done=true;})(std::move(operation));
        while(!done) {
            if(watch && interrupted) stop.request_stop();
            if(context.stopped()) context.restart();
            context.run_for(std::chrono::milliseconds(10));
        }
    };
    bool used_alternative=false;
    auto request=[&](bool try_alternative) {
        using namespace std::chrono_literals;
        if (try_alternative && automatic && watch->alternative && started<watch->alternative->expires && deadline-started>=75ms) {
            auto budget=std::min((deadline-started)/3,Clock::duration(500ms));
            run(started+budget,watch->alternative->port);
            used_alternative=result.has_value();
            if (!used_alternative) {
                watch->alternative.reset();
                advertisement={};
                validator={};
                location={};
                last_modified.clear();
            }
        }
        if (!used_alternative && !(watch && interrupted)) run(deadline);
    };
    auto saved_tag=[&]() -> std::string_view {
        if (options->cache) {
            if (cached.hit && url->target==cached.hit->metadata.response_target &&
                !entity_tag(cached.hit->metadata.etag).empty()) return cached.hit->metadata.etag;
        } else if (watch && watch->validator && url->target==watch->validator->target) return watch->validator->tag;
        return {};
    };
    std::vector<std::string> visited{url->target};
    for (unsigned hop=0;;++hop) {
        auto tag=saved_tag();
        policy.conditional=manage_validator && !tag.empty();
        if (policy.conditional) request_headers.push_back({"if-none-match",tag});
        advertisement={};
        validator={};
        location={};
        last_modified.clear();
        used_alternative=false;
        request(hop==0);
        if (policy.conditional) request_headers.pop_back();
        if (!result || !http::redirect_status(result->status) || (watch && interrupted)) break;
        if (hop>=selected->max_redirects || Clock::now()>=deadline) {
            result=std::unexpected("HTTPS rule redirect limit or deadline exceeded");
            break;
        }
        auto next=location.follow(*url);
        if (!next || std::ranges::find(visited,*next)!=visited.end()) {
            result=std::unexpected("HTTPS rule redirect has an invalid, cross-origin or repeated target");
            break;
        }
        url->target=std::move(*next);
        visited.push_back(url->target);
    }
    if(watch && interrupted)return 0;
    if (!result) {
        auto now=epoch_seconds();
        if (options->offline && cached.hit && offline_error(result.error()) &&
            now>=cached.hit->metadata.fetched_at && now<cached.hit->metadata.expires_at)
            return publish_rules(argv[5],cached.hit->body);
        std::cerr << result.error() << '\n';
        return 1;
    }
    auto updated_alternative=[&] {
        if (automatic && !used_alternative && (!advertisement.values.empty() || advertisement.invalid))
            watch->alternative=advertisement.select(started);
    };
    auto persist=[&](std::string_view body, ::state::RulesetMetadata metadata, bool unchanged=false) -> int {
        auto now=epoch_seconds();
        metadata.response_target=url->target;
        metadata.fetched_at=now;
        metadata.expires_at=now+86400;
        auto stored=options->cache->store(*key,cached.clear_epoch,std::move(metadata),body);
        if (!stored) return cache_error(stored.error());
        prewarm_srs_cache_sidecar(options->cache_root,*format,body,options->max_bytes.value_or(64ull*1024*1024));
        if (unchanged) {
            auto published=::rulefile::read_regular_file(argv[5]);
            if (published && *published==body) return 0;
        }
        return publish_rules(argv[5],body);
    };
    if (result->status==304) {
        auto valid=policy.conditional && !validator.invalid &&
            (!validator.seen || entity_tag(validator.value)==entity_tag(saved_tag()));
        if (options->cache && valid && cached.hit) {
            auto metadata=cached.hit->metadata;
            if (!last_modified.empty()) metadata.last_modified=last_modified;
            auto status=persist(cached.hit->body,std::move(metadata),true);
            if (!status) updated_alternative();
            return status;
        }
        if (options->cache && cached.hit) {
            auto discarded=options->cache->discard(*key,cached.clear_epoch,cached.hit->metadata.content_blake3);
            if (!discarded) return cache_error(discarded.error());
        }
        auto saved=::rulefile::read_regular_file(argv[5]);
        if (!valid || !watch || !watch->validator ||
            !saved || saved->size()>selected->max_bytes || rule_digest(*saved)!=watch->validator->digest) {
            if (watch) watch->validator.reset();
            std::cerr << "cannot validate unchanged rules; next refresh will request a complete response\n";
            return 1;
        }
        updated_alternative();
        return 0;
    }
    auto const& body=result->body;
    auto checked=validate_download(body,*format,pin);
    if (!checked) {std::cerr << checked.error() << '\n';return 1;}
    if (watch && interrupted) return 0;
    auto tag=validator.seen && !validator.invalid ? std::move(validator.value) : std::string{};
    auto status=options->cache ? persist(body,{.etag=tag,.last_modified=last_modified}) : publish_rules(argv[5],body);
    if (status) return status;
    if (watch && !options->cache && manage_validator) {
        auto digest=tag.empty() ? std::nullopt : rule_digest(body);
        if (digest) watch->validator=PublishedValidator{std::move(tag),std::move(url->target),*digest};
        else watch->validator.reset();
    }
    if (automatic && !used_alternative) watch->alternative=advertisement.select(started);
    return 0;
}

auto nexus_rule_fetch(int argc,char** argv) -> int {
    if (argc==3 && std::string_view(argv[1])=="--clear-cache") {
        auto path=std::filesystem::path(argv[2]);
        if (!path.is_absolute()) {std::cerr << "cache directory must be absolute\n";return 2;}
        auto cleared=::state::RulesetCache(path).clear();
        return cleared ? 0 : cache_error(cleared.error());
    }
    return fetch_once(argc,argv);
}

auto nexus_rule_watch(int argc,char** argv) -> int {
    using namespace std::chrono_literals;
    constexpr auto usage="usage: nexus rule watch <interval-ms> <config> <client> <https-url> <kdl|beve|srs> <output> [--sha256 <hex>] [--cache-dir <dir>] [--ruleset-cache-max-bytes <bytes>] [--offline-cache]\n";
    if(argc==2 && std::string_view(argv[1])=="--help") {std::cout << usage;return 0;}
    if(argc<7) {std::cerr << usage;return 2;}
    auto input=std::string_view(argv[1]);
    std::uint32_t ms=0;
    auto [end,error]=std::from_chars(input.data(),input.data()+input.size(),ms);
    if(error!=std::errc{} || end!=input.data()+input.size() || ms<100 || ms>86400000) {
        std::cerr << "watch interval must be 100..86400000 ms\n";return 2;
    }
    interrupted=0;
    Signals signals;
    if(!signals.installed()) {std::cerr << "cannot install rule watch signal handlers\n";return 1;}
    WatchState watch;
    while(!interrupted) {
        if(fetch_once(argc-1,argv+1,&watch)==2)return 2;
        auto next=Clock::now()+std::chrono::milliseconds(ms);
        while(!interrupted && Clock::now()<next) {
            auto slice=std::min(next,Clock::now()+50ms);
            if (watch.client) {
                auto& context=watch.client->executor();
                if (!context.stopped()) (void)context.run_until(slice);
            }
            if (!interrupted) std::this_thread::sleep_until(slice);
        }
    }
    return 0;
}

namespace {
    auto run_with_stop(corosio::io_context& context, std::stop_source& stop, std::stop_token external_stop,
        bool const& done) -> void {
        std::stop_callback cb(external_stop, [&]() noexcept { stop.request_stop(); context.stop(); });
        if (external_stop.stop_requested()) stop.request_stop();
        while (!done) {
            if (external_stop.stop_requested()) stop.request_stop();
            if (context.stopped()) context.restart();
            context.run_for(std::chrono::milliseconds(10));
        }
    }

    auto fetch_managed_ruleset_impl(config::Config const& config,std::string_view config_source,
        config::BlockRules const& spec,std::string_view previous_etag,bool offline_fallback,
        std::stop_token external_stop, void* client_pool)
        -> std::expected<cli::ManagedRulesetFetchResult,std::string> {
        auto url=parse_url(spec.url);
        using Format=::rules::InputFormat;
        auto format = cli::rule_input_format(spec.format);
        if (!url) return std::unexpected("invalid remote rule-set HTTPS URL: "+spec.url);
        std::optional<std::array<std::uint8_t,32>> pin;
        if (!spec.sha256.empty()) {
            pin=parse_sha256(spec.sha256);
            if (!pin) return std::unexpected("invalid remote rule-set SHA-256 pin");
        }
        auto cache_st = lookup_managed_ruleset_cache(config, *url, format, spec, pin);
        auto& cached = cache_st.cached;
        auto created=acquire_pooled_client(client_pool,config,spec.http_client,url->authority);
        if (!created) {
            if (offline_fallback && cached.hit)
                return cli::ManagedRulesetFetchResult{cached.hit->body,cached.hit->metadata.etag,true,cached.hit->metadata.fetched_at};
            return std::unexpected(created.error());
        }
        auto& client=*created->client;
        auto& context=client.executor();
        auto const& selected=client.settings();
        auto started=Clock::now();
        auto deadline=started+std::chrono::milliseconds(selected.timeout_ms);
        std::string active_etag(!previous_etag.empty() ? std::string(previous_etag) :
            (cached.hit ? cached.hit->metadata.etag : std::string{}));
        auto clean_tag=entity_tag(active_etag);
        std::vector<http::HeaderField> req_headers;
        bool conditional=!clean_tag.empty() && std::ranges::none_of(selected.headers,[](auto const& f) {
            return f.first=="if-none-match" || f.first=="if-modified-since" || f.first=="if-match";
        });
        if (conditional) req_headers.push_back({"if-none-match",clean_tag});
        EntityTag validator;
        std::string last_modified;
        auto on_header=[&](std::string_view name,std::string_view value) {
            validator.add(name,value);
            if (name=="last-modified" && value.size()<=128 && http::valid_header_field_value(value))
                last_modified=value;
        };
        std::optional<http::HttpHeaderConsumer> observe;
        observe.emplace(on_header);
        fetch::Result result=std::unexpected("HTTPS remote rule-set fetch did not complete");
        std::string body;
        auto consume=[&](std::string_view bytes,Clock::time_point) -> capy::task<bool> {
            body.append(bytes);
            co_return true;
        };
        auto op=client.get({url->target,req_headers,deadline,{},started,conditional,false},consume,observe);
        bool done=false;
        std::stop_source stop;
        context.restart();
        capy::run_async(context.get_executor(),stop.get_token(),[&](auto value) noexcept {
            if (value) result=fetch::Response{*value,std::move(body)};
            else result=std::unexpected(std::move(value.error()));
            done=true;
        },[&](std::exception_ptr) noexcept { done=true; })(std::move(op));
        run_with_stop(context, stop, external_stop, done);
        if (external_stop.stop_requested()) return std::unexpected("HTTPS remote rule-set fetch canceled");
        if (!result) {
            if (offline_fallback && cached.hit && offline_error(result.error()))
                return cli::ManagedRulesetFetchResult{cached.hit->body,cached.hit->metadata.etag,true,cached.hit->metadata.fetched_at};
            return std::unexpected(result.error());
        }
        release_pooled_client(client_pool,spec.http_client,url->authority,std::move(created->deps),std::move(created->client));
        if (result->status==304) {
            if (!conditional || validator.invalid || (validator.seen && entity_tag(validator.value)!=clean_tag))
                return std::unexpected("unexpected or mismatched HTTP 304 for remote rule-set");
            std::string tag=(validator.seen && !validator.invalid) ? validator.value : active_etag;
            auto now = epoch_seconds();
            if (cached.hit) {
                auto lm = last_modified.empty() ? std::string_view(cached.hit->metadata.last_modified) : std::string_view(last_modified);
                now = store_managed_ruleset_cache(cache_st, config, format, spec, url->target, tag, lm, cached.hit->body);
                return cli::ManagedRulesetFetchResult{cached.hit->body, std::move(tag), true, now};
            }
            return cli::ManagedRulesetFetchResult{{}, std::move(tag), true, now};
        }
        if (auto ok=validate_download(result->body,format,pin); !ok) return std::unexpected(ok.error());
        std::string tag=(validator.seen && !validator.invalid) ? validator.value : std::string{};
        auto now = store_managed_ruleset_cache(cache_st, config, format, spec, url->target, tag, last_modified, result->body);
        return cli::ManagedRulesetFetchResult{std::move(result->body), std::move(tag), false, now};
    }

    auto fetch_managed_provider_impl(config::Config const& config,
        config::ProxyProviderConfig const& spec, std::string_view previous_etag, bool offline_fallback,
        std::stop_token external_stop, void* client_pool)
        -> std::expected<cli::ManagedProviderFetchResult, std::string> {
        auto url = parse_url(spec.url);
        if (!url) return std::unexpected("invalid HTTPS provider URL: " + spec.url);
        auto csig = cli::http_client_signature(config, spec.http_client);
        std::filesystem::path cache_root = !spec.cache_dir.empty() ? std::filesystem::path(spec.cache_dir) :
            (config.state && !config.state->cache_directory.empty() ? std::filesystem::path(config.state->cache_directory) : std::filesystem::path{});
        std::optional<cli::ManagedProviderFetchResult> cached;
        if (!cache_root.empty()) {
            cached = cli::read_provider_cache(cache_root, spec.name, spec.url);
            if (cached && ((!cached->http_client_sig.empty() &&
                (cached->http_client_sig != csig || cached->format != spec.format)) ||
                !provider::parse_subscription(cached->body, spec.format).has_value()))
                cached.reset();
        }
        auto created = acquire_pooled_client(client_pool, config, spec.http_client, url->authority);
        if (!created) {
            if (offline_fallback && cached) return *cached;
            return std::unexpected(created.error());
        }
        auto& client = *created->client;
        auto& context = client.executor();
        auto const& selected = client.settings();
        auto started = Clock::now();
        auto deadline = started + std::chrono::milliseconds(selected.timeout_ms);
        std::string active_etag(!previous_etag.empty() ? std::string(previous_etag) :
            (cached ? cached->etag : std::string{}));
        auto clean_tag = entity_tag(active_etag);
        std::vector<http::HeaderField> req_headers;
        bool conditional = !clean_tag.empty() && std::ranges::none_of(selected.headers, [](auto const& f) {
            return f.first == "if-none-match" || f.first == "if-modified-since" || f.first == "if-match";
        });
        if (conditional) req_headers.push_back({"if-none-match", clean_tag});
        EntityTag validator;
        std::optional<provider::SubscriptionUserinfo> userinfo;
        auto on_header = [&](std::string_view name, std::string_view value) {
            std::string lname(name);
            for (auto& ch : lname) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
            validator.add(lname, value);
            if (lname == "subscription-userinfo" && value.size() <= 512) {
                if (auto ui = provider::parse_subscription_userinfo(value)) userinfo = *ui;
            }
        };
        std::optional<http::HttpHeaderConsumer> observe;
        observe.emplace(on_header);
        fetch::Result result = std::unexpected("HTTPS proxy-provider fetch did not complete");
        std::string body;
        auto consume = [&](std::string_view bytes, Clock::time_point) -> capy::task<bool> {
            body.append(bytes);
            co_return true;
        };
        auto op = client.get({url->target, req_headers, deadline, {}, started, conditional, false}, consume, observe);
        bool done = false;
        std::stop_source stop;
        context.restart();
        capy::run_async(context.get_executor(), stop.get_token(), [&](auto value) noexcept {
            if (value) result = fetch::Response{*value, std::move(body)};
            else result = std::unexpected(std::move(value.error()));
            done = true;
        }, [&](std::exception_ptr) noexcept { done = true; })(std::move(op));
        run_with_stop(context, stop, external_stop, done);
        if (external_stop.stop_requested()) return std::unexpected("HTTPS proxy-provider fetch canceled");
        if (!result) {
            if (offline_fallback && cached && offline_error(result.error())) return *cached;
            return std::unexpected(result.error());
        }
        release_pooled_client(client_pool, spec.http_client, url->authority, std::move(created->deps), std::move(created->client));
        auto now = epoch_seconds();
        if (result->status == 304) {
            if (!conditional || validator.invalid || (validator.seen && entity_tag(validator.value) != clean_tag))
                return std::unexpected("unexpected or mismatched HTTP 304 for proxy-provider");
            std::string tag = (validator.seen && !validator.invalid) ? validator.value : active_etag;
            cli::ManagedProviderFetchResult res{cached ? cached->body : std::string{}, std::move(tag),
                userinfo ? userinfo : (cached ? cached->userinfo : std::nullopt), true, now, csig, spec.format};
            if (!cache_root.empty() && !res.body.empty()) (void)cli::write_provider_cache(cache_root, spec.name, spec.url, res);
            return res;
        }
        if (result->body.empty()) return std::unexpected("empty HTTP 200 response for proxy-provider");
        if (auto parsed = provider::parse_subscription(result->body, spec.format); !parsed) return std::unexpected(parsed.error());
        std::string tag = (validator.seen && !validator.invalid) ? validator.value : std::string{};
        cli::ManagedProviderFetchResult res{std::move(result->body), std::move(tag), userinfo, false, now, csig, spec.format};
        if (!cache_root.empty()) (void)cli::write_provider_cache(cache_root, spec.name, spec.url, res);
        return res;
    }
}

extern "C" void nexus_register_builtin_http_fetchers() noexcept {
    cli::register_managed_ruleset_fetcher(&fetch_managed_ruleset_impl);
    cli::register_managed_ruleset_cache_probe(&probe_fresh_managed_ruleset_cache_impl);
    cli::register_managed_provider_fetcher(&fetch_managed_provider_impl);
    cli::register_managed_http_pool_factory(+[]() -> std::shared_ptr<void> { return std::make_shared<ManagedClientPool>(); });
}
