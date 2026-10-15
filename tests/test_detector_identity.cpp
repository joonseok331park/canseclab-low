#include "cansec/detector.hpp"

#include <array>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& name) {
    std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!condition) {
        ++failures;
    }
}

cansec::DetectionBaseline baseline_for(uint32_t id, cansec::IdType type,
                                       const std::set<uint8_t>& allowed_dlc) {
    cansec::IdProfile profile;
    profile.can_id = id;
    profile.id_type = type;
    profile.allowed_dlc = allowed_dlc;
    profile.rate_limit_100ms = 10;
    profile.max_identical_payload_run = 1;
    cansec::DetectionBaseline baseline;
    baseline.entries.push_back(profile);
    return baseline;
}

cansec::CanFrameRecord frame(uint32_t id, cansec::IdType type, uint8_t dlc) {
    cansec::CanFrameRecord record;
    record.timestamp_us = 1234567890123ULL;
    record.interface_name = "vcan-test";
    record.can_id = id;
    record.id_type = type;
    record.dlc = dlc;
    record.data = {1, 2, 3, 4, 5, 6, 7, 8};
    return record;
}

void expect_rule(const std::vector<cansec::Alert>& alerts, cansec::AlertRule rule,
                 const std::string& name) {
    check(alerts.size() == 1 && alerts[0].rule == rule && alerts[0].severity == cansec::Severity::High,
          name);
}

void expect_invalid(const cansec::DetectionBaseline& baseline, const cansec::CanFrameRecord& record,
                    const std::string& name) {
    try {
        cansec::detect_identity_rules(baseline, record, 100);
        check(false, name + " did not throw");
    } catch (const std::invalid_argument&) {
        check(true, name);
    } catch (const std::exception& error) {
        check(false, name + " raised wrong exception: " + error.what());
    }
}

void test_rule_pairs() {
    const auto baseline = baseline_for(0x100, cansec::IdType::Standard11, {8});
    const auto known = frame(0x100, cansec::IdType::Standard11, 8);
    check(cansec::detect_identity_rules(baseline, known, 999).empty(),
          "known ID with allowed DLC produces no identity alert");
    expect_rule(cansec::detect_identity_rules(baseline, frame(0x555, cansec::IdType::Standard11, 8), 999),
                cansec::AlertRule::UnknownId, "unknown ID produces one HIGH UNKNOWN_ID");
    expect_rule(cansec::detect_identity_rules(baseline, frame(0x100, cansec::IdType::Standard11, 4), 999),
                cansec::AlertRule::DlcMismatch, "known ID with wrong DLC produces one HIGH DLC_MISMATCH");
    expect_rule(cansec::detect_identity_rules(baseline, frame(0x555, cansec::IdType::Standard11, 4), 999),
                cansec::AlertRule::UnknownId, "unknown ID never adds a speculative DLC_MISMATCH");

    const auto extended_baseline = baseline_for(0x100, cansec::IdType::Extended29, {8});
    const auto extended = frame(0x100, cansec::IdType::Extended29, 8);
    check(cansec::detect_identity_rules(extended_baseline, extended, 999).empty(),
          "matching low numeric extended ID is known");
    expect_rule(cansec::detect_identity_rules(baseline, extended, 999),
                cansec::AlertRule::UnknownId, "extended frame does not match same numeric standard ID");
    expect_rule(cansec::detect_identity_rules(extended_baseline, known, 999),
                cansec::AlertRule::UnknownId, "standard frame does not match same numeric extended ID");
    expect_rule(cansec::detect_identity_rules(extended_baseline, frame(0x100, cansec::IdType::Extended29, 0), 999),
                cansec::AlertRule::DlcMismatch, "known extended ID with wrong DLC uses DLC rule");
}

void test_boundaries() {
    for (const auto type : {cansec::IdType::Standard11, cansec::IdType::Extended29}) {
        const uint32_t maximum = type == cansec::IdType::Standard11 ? 0x7FFU : 0x1FFFFFFFU;
        auto baseline = baseline_for(0, type, {0, 2, 8});
        baseline.entries.push_back(baseline_for(maximum, type, {0, 2, 8}).entries[0]);
        const std::string type_name = type == cansec::IdType::Standard11 ? "standard" : "extended";
        for (const auto id : {0U, maximum}) {
            for (const auto dlc : {0, 2, 8}) {
                check(cansec::detect_identity_rules(baseline, frame(id, type, static_cast<uint8_t>(dlc)), 100).empty(),
                      type_name + " zero/max ID accepts allowed DLC " + std::to_string(dlc));
            }
            expect_rule(cansec::detect_identity_rules(baseline, frame(id, type, 1), 100),
                        cansec::AlertRule::DlcMismatch, type_name + " zero/max ID rejects nonmember DLC");
        }
    }
    const auto baseline = baseline_for(0x100, cansec::IdType::Standard11, {8});
    expect_rule(cansec::detect_identity_rules(baseline, frame(0, cansec::IdType::Standard11, 0), 100),
                cansec::AlertRule::UnknownId, "unlisted numeric zero ID is still unknown");
    expect_rule(cansec::detect_identity_rules(baseline, frame(0x1FFFFFFF, cansec::IdType::Extended29, 8), 100),
                cansec::AlertRule::UnknownId, "unlisted maximum extended ID is still unknown");
}

void test_alert_fields() {
    const auto baseline = baseline_for(0x100, cansec::IdType::Standard11, {0, 2, 8});
    auto observed = frame(0x100, cansec::IdType::Standard11, 3);
    observed.data = {0xAA, 0xBB, 0xCC, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};
    const auto alerts = cansec::detect_identity_rules(baseline, observed, 1234567899999ULL);
    expect_rule(alerts, cansec::AlertRule::DlcMismatch, "field-check input produces DLC mismatch");
    if (alerts.size() == 1) {
        const auto& alert = alerts[0];
        check(alert.capture_ts_us == observed.timestamp_us && alert.alert_ts_us == 1234567899999ULL &&
                  alert.interface_name == observed.interface_name && alert.can_id == observed.can_id &&
                  alert.id_type == observed.id_type && alert.dlc == observed.dlc,
              "alert preserves capture time, supplied alert time, interface, typed ID and DLC");
        check(alert.data == std::array<uint8_t, 8>{0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0},
              "alert copies valid payload and zeroes unused source buffer bytes");
        check(alert.detail == "observed_dlc=3 allowed_dlc=0,2,8",
              "DLC detail explains observed and allowed lengths");
    }
    check(observed.data[3] == 0xEE && baseline.entries[0].allowed_dlc == std::set<uint8_t>{0, 2, 8},
          "detector does not mutate the input record or baseline");

    auto unknown = frame(0x123, cansec::IdType::Extended29, 8);
    unknown.timestamp_us = 0;
    const auto unknown_alerts = cansec::detect_identity_rules(baseline, unknown, std::numeric_limits<uint64_t>::max());
    expect_rule(unknown_alerts, cansec::AlertRule::UnknownId, "full payload input produces unknown ID");
    if (unknown_alerts.size() == 1) {
        const auto& alert = unknown_alerts[0];
        check(alert.capture_ts_us == 0 && alert.alert_ts_us == std::numeric_limits<uint64_t>::max() &&
                  alert.interface_name == unknown.interface_name && alert.can_id == 0x123 &&
                  alert.id_type == cansec::IdType::Extended29 && alert.dlc == 8 && alert.data == unknown.data,
              "unknown-ID alert preserves all eight bytes and boundary timestamps");
        check(alert.detail.find("0x123") != std::string::npos &&
                  alert.detail.find("extended") != std::string::npos &&
                  alert.detail.find("absent") != std::string::npos,
              "unknown-ID detail names the typed identity and missing baseline");
    }

    const auto nonzero_dlc_baseline = baseline_for(0x100, cansec::IdType::Standard11, {8});
    for (const auto id : {0x100U, 0x555U}) {
        auto empty = frame(id, cansec::IdType::Standard11, 0);
        empty.data.fill(0xFF);
        const auto zero_alerts = cansec::detect_identity_rules(nonzero_dlc_baseline, empty, 5);
        check(zero_alerts.size() == 1 && zero_alerts[0].data == std::array<uint8_t, 8>{},
              "zero-DLC alert contains no unused buffer bytes for either rule");
    }
}

void test_invalid_records() {
    const auto baseline = baseline_for(0x100, cansec::IdType::Standard11, {8});
    expect_invalid(baseline, frame(0x100, static_cast<cansec::IdType>(99), 8), "invalid enum is rejected");
    expect_invalid(baseline, frame(0x800, cansec::IdType::Standard11, 8), "standard ID above 11 bits is rejected");
    expect_invalid(baseline, frame(0x20000000, cansec::IdType::Extended29, 8), "extended ID above 29 bits is rejected");
    expect_invalid(baseline, frame(std::numeric_limits<uint32_t>::max(), cansec::IdType::Extended29, 8),
                   "extended ID containing flag bits is rejected");
    expect_invalid(baseline, frame(0x100, cansec::IdType::Standard11, 9), "DLC nine is rejected before copying");
    expect_invalid(baseline, frame(0x555, cansec::IdType::Standard11, 255),
                   "unknown ID with invalid DLC is rejected before making an alert");
}

}  // namespace

int main() {
    try {
        test_rule_pairs();
        test_boundaries();
        test_alert_fields();
        test_invalid_records();
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] unexpected test exception: " << error.what() << '\n';
        ++failures;
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "test_detector_identity passed.\n";
    return 0;
}
