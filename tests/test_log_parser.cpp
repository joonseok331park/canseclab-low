#include "cansec/logio.hpp"

#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& name) {
    if (!condition) {
        std::cerr << "[FAIL] " << name << "\n";
        ++failures;
        return;
    }

    std::cout << "[PASS] " << name << "\n";
}

template <typename Fn>
void expect_throw(Fn fn, const std::string& name) {
    try {
        fn();
        std::cerr << "[FAIL] " << name << " did not throw\n";
        ++failures;
    } catch (const std::exception&) {
        std::cout << "[PASS] " << name << "\n";
    }
}

}  // namespace

int main() {
    {
        auto parsed = cansec::parse_can_record_line(
            "(1730960000.123456) vcan0 100#0102030405060708");

        check(parsed.has_value(), "normal line parse returns record");

        const auto& record = parsed.value();

        check(record.timestamp_us == 1730960000123456ULL, "timestamp parse");
        check(record.interface_name == "vcan0", "interface parse");
        check(record.can_id == 0x100, "CAN ID parse");
        check(record.id_type == cansec::IdType::Standard11, "standard CAN ID type");
        check(record.dlc == 8, "DLC parse");
        check(record.data[0] == 0x01, "payload byte0 parse");
        check(record.data[7] == 0x08, "payload byte7 parse");

        check(
            cansec::format_can_record(record) ==
                "(1730960000.123456) vcan0 100#0102030405060708",
            "format parsed record");
    }

    {
        auto parsed = cansec::parse_can_record_line("   ");
        check(!parsed.has_value(), "blank line skip");
    }

    {
        auto parsed = cansec::parse_can_record_line("   # comment line");
        check(!parsed.has_value(), "comment line skip");
    }

    {
        auto parsed = cansec::parse_can_record_line(
            "(1730960000.123456) vcan0 100#abcdef");

        check(parsed.has_value(), "lowercase payload parse");

        check(
            cansec::format_can_record(parsed.value()) ==
                "(1730960000.123456) vcan0 100#ABCDEF",
            "lowercase payload normalizes to uppercase on format");
    }

    {
        auto parsed = cansec::parse_can_record_line(
            "(1730960000.123456) vcan0 1ABCDEFF#0102");

        check(parsed.has_value(), "extended CAN ID parse");
        check(parsed.value().id_type == cansec::IdType::Extended29, "extended CAN ID type");
        check(parsed.value().can_id == 0x1ABCDEFF, "extended CAN ID value");
    }

    expect_throw([] {
        cansec::parse_can_record_line("1730960000.123456) vcan0 100#0102");
    }, "invalid timestamp reject");

    expect_throw([] {
        cansec::parse_can_record_line("(1730960000.123456) vcan0 XYZ#0102");
    }, "invalid CAN ID reject");

    expect_throw([] {
        cansec::parse_can_record_line("(1730960000.123456) vcan0 100#010");
    }, "odd-length payload reject");

    expect_throw([] {
        cansec::parse_can_record_line("(1730960000.123456) vcan0 100#010203040506070809");
    }, "payload longer than 8 bytes reject");

    expect_throw([] {
        cansec::parse_can_record_line("(1730960000.123456) vcan0 20000000#0102");
    }, "CAN ID beyond 29-bit reject");

    {
        const auto record = cansec::parse_can_record_line("(1.1) vcan0 00000100#").value();
        check(record.id_type == cansec::IdType::Extended29, "low-value extended ID preserves type");
        check(record.dlc == 0, "zero-length payload accepted");
        check(cansec::format_can_record(record) == "(1.100000) vcan0 00000100#",
              "low-value extended ID and short timestamp round trip");
    }
    {
        const auto record = cansec::parse_can_record_line("(18446744073709.551615) vcan0 7FF#00").value();
        check(record.timestamp_us == std::numeric_limits<uint64_t>::max(), "maximum timestamp accepted exactly");
        check(record.id_type == cansec::IdType::Standard11, "maximum standard ID remains standard");
    }
    expect_throw([] {
        cansec::parse_can_record_line("(18446744073709.551616) vcan0 100#00");
    }, "timestamp one microsecond above uint64 limit rejected");
    expect_throw([] {
        cansec::parse_can_record_line("(18446744073710.000000) vcan0 100#00");
    }, "timestamp multiplication overflow rejected");
    expect_throw([] {
        cansec::parse_can_record_line("(1.000000) vcan0 000000100#00");
    }, "overlong zero-padded CAN ID rejected");
    expect_throw([] {
        cansec::parse_can_record_line("(1.000000) vcan0 100#GG");
    }, "non-hex payload rejected");
    expect_throw([] {
        cansec::parse_can_record_line("(1.000000) vcan0 100#00 extra");
    }, "extra token rejected");

    if (failures > 0) {
        std::cerr << failures << " test(s) failed.\n";
        return 1;
    }

    std::cout << "test_log_parser passed.\n";
    return 0;
}
