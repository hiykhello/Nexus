export module desktop.mini_json;

import std;

export namespace desktop {
    struct JsonValue;
    using JsonArray = std::vector<JsonValue>;
    using JsonObject = std::vector<std::pair<std::string, JsonValue>>;

    struct JsonValue {
        using Storage = std::variant<std::monostate, bool, std::int64_t, double, std::string, JsonArray, JsonObject>;
        Storage data;

        JsonValue() = default;
        JsonValue(std::nullptr_t) : data(std::monostate{}) {}
        JsonValue(bool v) : data(v) {}
        JsonValue(std::int64_t v) : data(v) {}
        JsonValue(int v) : data(static_cast<std::int64_t>(v)) {}
        JsonValue(double v) : data(v) {}
        JsonValue(std::string v) : data(std::move(v)) {}
        JsonValue(std::string_view v) : data(std::string(v)) {}
        JsonValue(char const* v) : data(v ? std::string(v) : std::string{}) {}
        JsonValue(JsonArray v) : data(std::move(v)) {}
        JsonValue(JsonObject v) : data(std::move(v)) {}

        [[nodiscard]] auto is_null() const noexcept -> bool { return std::holds_alternative<std::monostate>(data); }
        [[nodiscard]] auto is_bool() const noexcept -> bool { return std::holds_alternative<bool>(data); }
        [[nodiscard]] auto is_i64() const noexcept -> bool { return std::holds_alternative<std::int64_t>(data); }
        [[nodiscard]] auto is_double() const noexcept -> bool { return std::holds_alternative<double>(data); }
        [[nodiscard]] auto is_string() const noexcept -> bool { return std::holds_alternative<std::string>(data); }
        [[nodiscard]] auto is_array() const noexcept -> bool { return std::holds_alternative<JsonArray>(data); }
        [[nodiscard]] auto is_object() const noexcept -> bool { return std::holds_alternative<JsonObject>(data); }
    };

    [[nodiscard]] auto json_parse(std::string_view input) -> std::expected<JsonValue, std::string>;
    [[nodiscard]] auto json_stringify(JsonValue const& value, bool pretty = true) -> std::string;
    [[nodiscard]] auto json_escape_utf8(std::string_view text) -> std::string;

    [[nodiscard]] auto json_find(JsonObject const& obj, std::string_view key) noexcept -> JsonValue const*;
    [[nodiscard]] auto json_get_string(JsonObject const& obj, std::string_view key, std::string_view fallback = {}) -> std::string;
    [[nodiscard]] auto json_get_bool(JsonObject const& obj, std::string_view key, bool fallback = false) noexcept -> bool;
    [[nodiscard]] auto json_get_i64(JsonObject const& obj, std::string_view key, std::int64_t fallback = 0) noexcept -> std::int64_t;
    [[nodiscard]] auto json_get_string_vec(JsonObject const& obj, std::string_view key) -> std::vector<std::string>;
    [[nodiscard]] auto json_get_string_map(JsonObject const& obj, std::string_view key) -> std::vector<std::pair<std::string, std::string>>;

    [[nodiscard]] auto json_from_string_vec(std::vector<std::string> const& items) -> JsonValue;
    [[nodiscard]] auto json_from_string_map(std::vector<std::pair<std::string, std::string>> const& items) -> JsonValue;
}
