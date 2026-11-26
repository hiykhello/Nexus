// Wave 30-32 extended Control API JSON parsers (outbounds health, probes, rules, live DNS query, FakeIP flush, log entries).
module desktop.http_control;

import std;
import desktop.mini_json;

namespace desktop {
    namespace {
        auto parse_u64_field(JsonObject const& o, std::string_view key) -> std::uint64_t {
            auto const* v = json_find(o, key);
            if (!v) return 0;
            if (auto const* i = std::get_if<std::int64_t>(&v->data)) {
                return *i >= 0 ? static_cast<std::uint64_t>(*i) : 0;
            }
            if (auto const* d = std::get_if<double>(&v->data)) {
                return *d >= 0.0 ? static_cast<std::uint64_t>(*d) : 0;
            }
            if (auto const* s = std::get_if<std::string>(&v->data)) {
                std::uint64_t out = 0;
                auto [ptr, ec] = std::from_chars(s->data(), s->data() + s->size(), out);
                return ec == std::errc{} ? out : 0;
            }
            return 0;
        }

        // Extracts error text from Core's nested {"error":{"code":"...","message":"..."}} or flat {"message"/"error":"..."}.
        auto extract_api_error(JsonObject const& obj) -> std::string {
            if (auto const* err_val = json_find(obj, "error"); err_val && err_val->is_object()) {
                auto const& err_obj = std::get<JsonObject>(err_val->data);
                if (auto msg = json_get_string(err_obj, "message"); !msg.empty()) return msg;
                if (auto code = json_get_string(err_obj, "code"); !code.empty()) return code;
            }
            if (auto msg = json_get_string(obj, "message"); !msg.empty()) return msg;
            return json_get_string(obj, "error");
        }
    }

    auto parse_outbounds_json(std::string_view json) -> std::vector<OutboundGroupSnapshot> {
        std::vector<OutboundGroupSnapshot> groups;
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) return groups;
        auto const& root = std::get<JsonObject>(parsed->data);
        auto const* arr = json_find(root, "groups");
        if (!arr || !arr->is_array()) return groups;

        for (auto const& elem : std::get<JsonArray>(arr->data)) {
            if (!elem.is_object()) continue;
            auto const& obj = std::get<JsonObject>(elem.data);
            OutboundGroupSnapshot grp{};
            grp.tag = json_get_string(obj, "name");
            if (grp.tag.empty()) grp.tag = json_get_string(obj, "tag");
            grp.mode = json_get_string(obj, "mode");
            grp.active = json_get_string(obj, "selected");
            if (grp.active.empty()) grp.active = json_get_string(obj, "active");
            grp.manual_override = json_get_bool(obj, "override", false);

            if (auto const* marr = json_find(obj, "members"); marr && marr->is_array()) {
                for (auto const& melem : std::get<JsonArray>(marr->data)) {
                    if (!melem.is_object()) continue;
                    auto const& mobj = std::get<JsonObject>(melem.data);
                    OutboundMemberSnapshot m{};
                    m.name = json_get_string(mobj, "name");
                    m.state = json_get_string(mobj, "state");
                    m.latency_ms = json_get_i64(mobj, "latency_ms", -1);
                    m.ewma_ms = json_get_i64(mobj, "ewma_ms", -1);
                    m.last_status = static_cast<int>(json_get_i64(mobj, "last_status", 0));
                    m.breaker_open = json_get_bool(mobj, "breaker_open", false);
                    m.selected = (!grp.active.empty() && m.name == grp.active);
                    m.overridden = m.selected && grp.manual_override;
                    if (!m.name.empty()) grp.members.push_back(std::move(m));
                }
            }
            if (!grp.tag.empty()) groups.push_back(std::move(grp));
        }
        return groups;
    }

    auto parse_outbound_probe_json(std::string_view json) -> OutboundProbeResult {
        OutboundProbeResult out{};
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) {
            out.error = json.empty() ? "empty probe response" : "malformed probe JSON";
            return out;
        }
        auto const& obj = std::get<JsonObject>(parsed->data);
        out.outbound = json_get_string(obj, "outbound");
        out.resolved_outbound = json_get_string(obj, "resolved_outbound");
        out.state = json_get_string(obj, "state");
        out.latency_ms = json_get_i64(obj, "latency_ms", -1);
        out.status_code = static_cast<int>(json_get_i64(obj, "status_code", 0));
        out.url = json_get_string(obj, "url");
        out.error = extract_api_error(obj);
        out.ok = (out.state == "healthy" || out.state == "ok" || out.state == "up") && out.latency_ms >= 0;
        return out;
    }

    auto parse_log_entry_json(std::string_view json) -> std::optional<LogEntrySnapshot> {
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) return std::nullopt;
        auto const& obj = std::get<JsonObject>(parsed->data);
        LogEntrySnapshot e{};
        e.seq = parse_u64_field(obj, "seq");
        e.level = json_get_string(obj, "level");
        e.domain = json_get_string(obj, "domain");
        auto ev_code = json_get_i64(obj, "event_code", -1);
        if (ev_code < 0) ev_code = json_get_i64(obj, "event", 0);
        e.event_code = static_cast<std::uint32_t>(std::max<std::int64_t>(0, ev_code));
        e.message = json_get_string(obj, "message");
        if (e.level.empty() && e.message.empty()) return std::nullopt;
        return e;
    }

    auto parse_rules_json(std::string_view json) -> std::vector<RuleEntrySnapshot> {
        std::vector<RuleEntrySnapshot> out;
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) return out;
        auto const& root = std::get<JsonObject>(parsed->data);
        auto const* arr = json_find(root, "rules");
        if (!arr || !arr->is_array()) return out;
        for (auto const& elem : std::get<JsonArray>(arr->data)) {
            if (!elem.is_object()) continue;
            auto const& obj = std::get<JsonObject>(elem.data);
            RuleEntrySnapshot r{};
            r.index = static_cast<std::uint32_t>(json_get_i64(obj, "index", 0));
            r.type = json_get_string(obj, "type");
            r.action = json_get_string(obj, "action");
            r.target = json_get_string(obj, "target");
            r.summary = json_get_string(obj, "summary");
            out.push_back(std::move(r));
        }
        return out;
    }

    auto parse_dns_query_json(std::string_view json) -> DnsQueryResult {
        DnsQueryResult out{};
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) {
            out.error = json.empty() ? "empty DNS response" : "malformed DNS query JSON";
            return out;
        }
        auto const& obj = std::get<JsonObject>(parsed->data);
        out.error = extract_api_error(obj);
        out.name = json_get_string(obj, "name");
        out.type = json_get_string(obj, "type");
        out.rcode = static_cast<int>(json_get_i64(obj, "rcode", -1));
        out.rcode_name = json_get_string(obj, "rcode_name");
        out.ttl = static_cast<std::uint32_t>(std::max<std::int64_t>(0, json_get_i64(obj, "ttl", 0)));
        out.elapsed_ms = parse_u64_field(obj, "elapsed_ms");
        if (auto const* arr = json_find(obj, "answers"); arr && arr->is_array()) {
            for (auto const& elem : std::get<JsonArray>(arr->data)) {
                if (!elem.is_object()) continue;
                auto const& a = std::get<JsonObject>(elem.data);
                out.answers.push_back({
                    json_get_string(a, "name"),
                    json_get_string(a, "type"),
                    static_cast<std::uint32_t>(std::max<std::int64_t>(0, json_get_i64(a, "ttl", 0))),
                    json_get_string(a, "data"),
                });
            }
        }
        out.ok = out.error.empty() && out.rcode >= 0;
        return out;
    }

    auto parse_fakeip_flush_json(std::string_view json) -> FakeIpFlushResult {
        FakeIpFlushResult out{};
        auto parsed = json_parse(json);
        if (!parsed || !parsed->is_object()) {
            out.error = json.empty() ? "empty FakeIP flush response" : "malformed FakeIP flush JSON";
            return out;
        }
        auto const& obj = std::get<JsonObject>(parsed->data);
        out.error = extract_api_error(obj);
        out.flushed = parse_u64_field(obj, "flushed");
        out.fakeip = json_get_bool(obj, "fakeip", false);
        out.ok = out.error.empty() && (out.fakeip || json_find(obj, "flushed") != nullptr);
        return out;
    }
}
