#include "cansec/alert_json.hpp"

#include <iostream>
#include <limits>
#include <locale>
#include <stdexcept>
#include <string>

namespace {
int failures = 0;
void check(bool value, const std::string& name) {
    std::cout << (value ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!value) ++failures;
}
template <typename Action>
void invalid(Action action, const std::string& name) {
    try { action(); check(false, name); }
    catch (const std::invalid_argument&) { check(true, name); }
}
struct GroupDigits : std::numpunct<char> {
    char do_thousands_sep() const override { return ','; }
    std::string do_grouping() const override { return "\3"; }
};
}

int main(int argc, char** argv) {
    cansec::Alert a;
    a.capture_ts_us = 123456789;
    a.alert_ts_us = 123456790;
    a.interface_name = "vcan0";
    a.can_id = 0x123;
    a.rule = cansec::AlertRule::FixedByteViolation;
    a.severity = cansec::Severity::Medium;
    a.dlc = 3;
    a.data = {0, 0xAA, 0xFF, 0xDD, 0xEE, 0xEE, 0xEE, 0xEE};
    a.detail = "changed";
    // Optional machine-readable fixture for Python's independent JSON parser.
    if (argc == 2 && std::string(argv[1]) == "--emit-fixtures") {
        a.interface_name = "bus\"\\\n";
        a.detail = std::string("nul\0tab\t", 8) + u8"한글";
        std::cout << cansec::format_alert_json(a) << '\n';
        a.id_type = cansec::IdType::Extended29;
        a.capture_ts_us = std::numeric_limits<uint64_t>::max();
        a.dlc = 0;
        std::cout << cansec::format_alert_json(a) << '\n';
        return 0;
    }
    const std::string expected = "{\"capture_ts_us\":123456789,\"alert_ts_us\":123456790,\"if\":\"vcan0\",\"rule\":\"FIXED_BYTE_VIOLATION\",\"severity\":\"MEDIUM\",\"can_id\":\"0x123\",\"id_type\":\"standard\",\"dlc\":3,\"data\":\"00AAFF\",\"detail\":\"changed\"}";
    check(cansec::format_alert_json(a) == expected, "required fields, typed ID, uppercase valid payload and exact integers");
    const auto old_locale = std::locale();
    std::locale::global(std::locale(old_locale, new GroupDigits));
    check(cansec::format_alert_json(a) == expected, "JSON numbers are independent of global locale");
    std::locale::global(old_locale);
    a.interface_name = "a\"b\\c\n";
    a.detail = std::string("\0\t\r\b\f", 5);
    auto text = cansec::format_alert_json(a);
    check(text.find("a\\\"b\\\\c\\u000A") != std::string::npos, "quote, backslash and newline escaped");
    check(text.find("\\u0000\\u0009\\u000D\\u0008\\u000C") != std::string::npos, "NUL and control characters escaped");
    check(text.find('\n') == std::string::npos, "one object has no physical newline");
    a.detail = u8"한글 😀";
    check(cansec::format_alert_json(a).find(a.detail) != std::string::npos, "valid UTF-8 text preserved");
    for (const std::string& bad : {std::string("\x80"), std::string("\xC0\xAF"),
         std::string("\xE0\x80\x80"), std::string("\xED\xA0\x80"),
         std::string("\xF4\x90\x80\x80"), std::string("\xE2\x82"), std::string("\xC2x")}) {
        a.detail = bad;
        invalid([&] { cansec::format_alert_json(a); }, "invalid UTF-8 rejected");
    }
    a.interface_name = "vcan0"; a.detail = "ok";
    a.capture_ts_us = std::numeric_limits<uint64_t>::max();
    a.alert_ts_us = 0;
    a.dlc = 0;
    text = cansec::format_alert_json(a);
    check(text.find("18446744073709551615") != std::string::npos && text.find("\"alert_ts_us\":0") != std::string::npos, "uint64 timestamps are not rounded");
    check(text.find("\"data\":\"\"") != std::string::npos, "empty payload has empty data string");
    a.id_type = cansec::IdType::Extended29;
    check(cansec::format_alert_json(a).find("\"id_type\":\"extended\"") != std::string::npos, "low extended numeric ID retains its type");
    a.can_id = 0x1FFFFFFF; a.dlc = 8;
    check(cansec::format_alert_json(a).find("00AAFFDDEEEEEEEE") != std::string::npos, "full eight-byte payload serialized");
    const char* rules[] = {"UNKNOWN_ID", "DLC_MISMATCH", "PERIOD_VIOLATION", "RATE_SPIKE", "FIXED_BYTE_VIOLATION", "REPLAY_BURST"};
    for (int i = 0; i < 6; ++i) {
        a.rule = static_cast<cansec::AlertRule>(i);
        check(cansec::format_alert_json(a).find(rules[i]) != std::string::npos, std::string("rule ") + rules[i]);
    }
    a.severity = cansec::Severity::Low;
    check(cansec::format_alert_json(a).find("\"severity\":\"LOW\"") != std::string::npos, "LOW severity");
    a.severity = cansec::Severity::High;
    check(cansec::format_alert_json(a).find("\"severity\":\"HIGH\"") != std::string::npos, "HIGH severity");
    a.dlc = 9; invalid([&] { cansec::format_alert_json(a); }, "invalid DLC rejected"); a.dlc = 0;
    a.can_id = 0x20000000; invalid([&] { cansec::format_alert_json(a); }, "extended ID overflow rejected");
    a.id_type = cansec::IdType::Standard11; a.can_id = 0x800;
    invalid([&] { cansec::format_alert_json(a); }, "standard ID overflow rejected"); a.can_id = 0;
    a.id_type = static_cast<cansec::IdType>(99); invalid([&] { cansec::format_alert_json(a); }, "invalid ID type rejected"); a.id_type = cansec::IdType::Standard11;
    a.rule = static_cast<cansec::AlertRule>(99); invalid([&] { cansec::format_alert_json(a); }, "invalid rule rejected"); a.rule = cansec::AlertRule::UnknownId;
    a.severity = static_cast<cansec::Severity>(99); invalid([&] { cansec::format_alert_json(a); }, "invalid severity rejected");
    return failures == 0 ? 0 : 1;
}
