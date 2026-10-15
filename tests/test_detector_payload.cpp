#include "cansec/detector.hpp"

#include <algorithm>
#include <array>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

int failures = 0;
using Rule = cansec::AlertRule;
using Level = cansec::Severity;
using Type = cansec::IdType;

void check(bool condition, const std::string& name) {
    std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!condition) ++failures;
}

cansec::DetectionBaseline policy(int maximum_run = 2) {
    cansec::IdProfile entry;
    entry.can_id = 0x100;
    entry.allowed_dlc = {2};
    entry.rate_limit_100ms = 100;
    entry.max_identical_payload_run = maximum_run;
    cansec::DetectionBaseline baseline;
    baseline.entries.push_back(entry);
    return baseline;
}

cansec::CanFrameRecord frame(uint64_t timestamp, std::initializer_list<uint8_t> payload,
                             uint32_t id = 0x100, const std::string& interface = "vcan0",
                             Type type = Type::Standard11) {
    cansec::CanFrameRecord record;
    record.timestamp_us = timestamp;
    record.interface_name = interface;
    record.can_id = id;
    record.id_type = type;
    record.dlc = static_cast<uint8_t>(payload.size());
    record.data.fill(0xEE);
    std::copy(payload.begin(), payload.end(), record.data.begin());
    return record;
}

void rules(const std::vector<cansec::Alert>& alerts, std::initializer_list<Rule> expected,
           const std::string& name) {
    bool match = alerts.size() == expected.size();
    std::size_t index = 0;
    for (const auto rule : expected) {
        if (index >= alerts.size() || alerts[index].rule != rule) match = false;
        ++index;
    }
    check(match, name);
}

void single(const std::vector<cansec::Alert>& alerts, Rule rule, Level severity,
            const std::string& detail, const std::string& name) {
    check(alerts.size() == 1 && alerts[0].rule == rule && alerts[0].severity == severity &&
              alerts[0].detail == detail, name);
}

template <typename Action>
void invalid(Action action, const std::string& name) {
    try {
        action();
        check(false, name + " did not throw");
    } catch (const std::invalid_argument&) {
        check(true, name);
    } catch (const std::exception& error) {
        check(false, name + " raised another exception: " + error.what());
    }
}

void test_fixed_masks() {
    auto baseline = policy(100);
    baseline.entries[0].fixed_mask[0] = 0xFF;
    baseline.entries[0].fixed_value[0] = 0xAA;
    cansec::Detector full_byte(baseline);
    rules(full_byte.process(frame(0, {0xAA, 0x01}), 0), {}, "matching fixed byte is normal");
    single(full_byte.process(frame(1, {0xAB, 0x01}), 0), Rule::FixedByteViolation, Level::Medium,
           "fixed_byte_mismatches=[index=0 observed=0xAB expected=0xAA effective_mask=0xFF]",
           "changed fixed byte gives one MEDIUM alert with exact observed/expected detail");
    rules(full_byte.process(frame(2, {0xAA, 0x99}), 0), {}, "unmasked byte may change freely");

    baseline.entries[0].ignore_mask[0] = 0xFF;
    cansec::Detector ignored(baseline);
    rules(ignored.process(frame(0, {0x00, 0x01}), 0), {}, "fully ignored fixed byte is not compared");
    baseline.entries[0].fixed_mask[0] = 0xF0;
    baseline.entries[0].ignore_mask[0] = 0;
    baseline.entries[0].fixed_value[0] = 0xA5;
    cansec::Detector partial(baseline);
    rules(partial.process(frame(0, {0xAF, 0x01}), 0), {}, "partial mask ignores differing unmasked bits");
    single(partial.process(frame(1, {0xBF, 0x01}), 0), Rule::FixedByteViolation, Level::Medium,
           "fixed_byte_mismatches=[index=0 observed=0xBF expected=0xA5 effective_mask=0xF0]",
           "partial mask detects a changed selected bit");
    baseline.entries[0].fixed_mask[0] = 0xF3;
    baseline.entries[0].ignore_mask[0] = 0x03;
    cansec::Detector bitwise_ignore(baseline);
    rules(bitwise_ignore.process(frame(0, {0xAF, 0x01}), 0), {}, "ignore bits are removed from the fixed bit mask");
    single(bitwise_ignore.process(frame(1, {0xB3, 0x01}), 0), Rule::FixedByteViolation, Level::Medium,
           "fixed_byte_mismatches=[index=0 observed=0xB3 expected=0xA5 effective_mask=0xF0]",
           "remaining fixed bits still detect a violation after partial ignore");

    baseline = policy(100);
    baseline.entries[0].allowed_dlc = {8};
    baseline.entries[0].fixed_mask = {0xFF, 0, 0xFF, 0, 0, 0, 0, 0x0F};
    baseline.entries[0].fixed_value = {0xA1, 0, 0x03, 0, 0, 0, 0, 0x05};
    baseline.entries[0].ignore_mask[0] = 0x0F;
    cansec::Detector multiple(baseline);
    single(multiple.process(frame(0, {0xB2, 0x99, 0x04, 0, 0, 0, 0, 0x06}), 0),
           Rule::FixedByteViolation, Level::Medium,
           "fixed_byte_mismatches=[index=0 observed=0xB2 expected=0xA1 effective_mask=0xF0; "
           "index=2 observed=0x04 expected=0x03 effective_mask=0xFF; "
           "index=7 observed=0x06 expected=0x05 effective_mask=0x0F]",
           "one fixed alert lists all differing indexes including byte seven");
}

void test_present_bytes_only() {
    auto baseline = policy(100);
    baseline.entries[0].fixed_mask[1] = 0xFF;
    baseline.entries[0].fixed_value[1] = 0xAA;
    cansec::Detector short_frame(baseline);
    rules(short_frame.process(frame(0, {0x01}), 0), {Rule::DlcMismatch},
          "missing fixed byte is handled only by DLC rule, not compared against unused tail");
    baseline.entries[0].allowed_dlc = {1};
    cansec::Detector allowed_short(baseline);
    rules(allowed_short.process(frame(0, {0x01}), 0), {}, "allowed short DLC does not compare an absent byte");
    baseline.entries[0].allowed_dlc = {0};
    baseline.entries[0].fixed_mask.fill(0xFF);
    baseline.entries[0].fixed_value.fill(0xAA);
    cansec::Detector no_payload(baseline);
    rules(no_payload.process(frame(0, {}), 0), {}, "zero DLC has no present bytes to compare");
    baseline.entries[0].allowed_dlc = {2};
    cansec::Detector invalid_zero(baseline);
    rules(invalid_zero.process(frame(0, {}), 0), {Rule::DlcMismatch}, "wrong zero DLC never invents fixed-byte data");
    cansec::Detector invalid_length(baseline);
    rules(invalid_length.process(frame(0, {0xAB}), 0), {Rule::DlcMismatch, Rule::FixedByteViolation},
          "wrong DLC still compares its present fixed byte");
}

void test_replay_threshold_and_reset() {
    cansec::Detector detector(policy(2));
    rules(detector.process(frame(0, {0xAA, 0xBB}), 0), {}, "first accepted payload starts at run one");
    rules(detector.process(frame(0, {0xAA, 0xBB}), 0), {}, "run equal to threshold is allowed at the same timestamp");
    single(detector.process(frame(0, {0xAA, 0xBB}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=3 threshold=2", "first excessive raw payload run gives HIGH replay alert");
    single(detector.process(frame(0, {0xAA, 0xBB}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=4 threshold=2", "each continuing excessive run emits another replay alert");
    rules(detector.process(frame(1, {0xAA, 0xBC}), 0), {}, "changed valid payload resets run to one");
    rules(detector.process(frame(2, {0xAA, 0xBC}), 0), {}, "new raw payload reaches its own threshold");
    single(detector.process(frame(3, {0xAA, 0xBC}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=3 threshold=2", "changed payload can start a new excessive run");
    rules(detector.process(frame(4, {0xAA, 0xBB}), 0), {}, "returning to an earlier payload resets rather than accumulating history");

    cansec::Detector no_time_cutoff(policy(1));
    no_time_cutoff.process(frame(0, {1, 2}), 0);
    single(no_time_cutoff.process(frame(std::numeric_limits<uint64_t>::max(), {1, 2}), 0),
           Rule::ReplayBurst, Level::High, "identical_payload_run=2 threshold=1",
           "consecutive equal payloads have no time cutoff even across the full timestamp range");
}

void test_dlc_and_raw_payload_equality() {
    auto baseline = policy(1);
    baseline.entries[0].allowed_dlc = {1, 2};
    cansec::Detector lengths(baseline);
    lengths.process(frame(0, {0xAA, 0xBB}), 0);
    rules(lengths.process(frame(1, {0xAA}), 0), {}, "changed DLC resets even when the shared prefix matches");
    single(lengths.process(frame(2, {0xAA}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=2 threshold=1", "repeated short payload starts its own run");
    rules(lengths.process(frame(3, {0xAA, 0xBB}), 0), {}, "restored DLC again resets to one");

    cansec::Detector wrong_dlc(policy(1));
    wrong_dlc.process(frame(0, {0xAA, 0xBB}), 0);
    rules(wrong_dlc.process(frame(1, {0xAA}), 0), {Rule::DlcMismatch}, "wrong DLC still resets the raw payload run");
    const auto repeated_wrong = wrong_dlc.process(frame(2, {0xAA}), 0);
    rules(repeated_wrong, {Rule::DlcMismatch, Rule::ReplayBurst}, "wrong-DLC frames remain eligible for replay detection");
    check(repeated_wrong.size() == 2 && repeated_wrong[1].detail == "identical_payload_run=2 threshold=1",
          "DLC violation contributed to the exact replay count");

    baseline = policy(1);
    baseline.entries[0].fixed_mask.fill(0xFF);
    baseline.entries[0].ignore_mask.fill(0xFF);
    cansec::Detector raw_ignored(baseline);
    raw_ignored.process(frame(0, {0x10, 0xBB}), 0);
    rules(raw_ignored.process(frame(1, {0x20, 0xBB}), 0), {}, "change in ignored byte resets raw replay equality");
    single(raw_ignored.process(frame(2, {0x20, 0xBB}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=2 threshold=1", "ignore mask does not prevent replay detection of equal raw bytes");

    cansec::Detector tails(policy(1));
    auto first = frame(0, {0xAA, 0xBB});
    auto second = frame(1, {0xAA, 0xBB});
    second.data[7] = 0xDD;
    tails.process(first, 0);
    const auto same_valid = tails.process(second, 5);
    single(same_valid, Rule::ReplayBurst, Level::High, "identical_payload_run=2 threshold=1",
           "unused buffer tail differences do not reset replay equality");
    check(same_valid.size() == 1 && same_valid[0].data == std::array<uint8_t, 8>{0xAA, 0xBB, 0, 0, 0, 0, 0, 0},
          "replay alert does not leak unused source buffer bytes");

    baseline = policy(1);
    baseline.entries[0].allowed_dlc = {0};
    cansec::Detector empty_payload(baseline);
    empty_payload.process(frame(0, {}), 0);
    auto empty = frame(1, {});
    empty.data.fill(0xDD);
    const auto zero_alert = empty_payload.process(empty, 5);
    single(zero_alert, Rule::ReplayBurst, Level::High, "identical_payload_run=2 threshold=1",
           "two zero-DLC frames are equal regardless of their unused buffers");
    check(zero_alert.size() == 1 && zero_alert[0].dlc == 0 && zero_alert[0].data == std::array<uint8_t, 8>{},
          "zero-DLC replay alert has an empty payload");
}

void test_interleaved_streams() {
    auto baseline = policy(1);
    auto other = baseline.entries[0];
    other.can_id = 0x200;
    other.id_type = Type::Extended29;
    baseline.entries.push_back(other);
    cansec::Detector detector(baseline);
    rules(detector.process(frame(10000, {1, 2}), 0), {}, "standard stream starts its own payload run");
    rules(detector.process(frame(5, {3, 4}, 0x200, "vcan0", Type::Extended29), 0), {}, "another typed ID starts independently");
    rules(detector.process(frame(0, {1, 2}, 0x100, "vcan1"), 0), {}, "same typed ID on another interface starts independently");
    single(detector.process(frame(10001, {1, 2}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=2 threshold=1", "other streams do not reset the first stream's consecutive run");
    single(detector.process(frame(6, {3, 4}, 0x200, "vcan0", Type::Extended29), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=2 threshold=1", "extended ID retains its own payload run");
    single(detector.process(frame(1, {1, 2}, 0x100, "vcan1"), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=2 threshold=1", "other interface retains its own payload run");
    rules(detector.process(frame(9, {8, 9}, 0x100, "vcan0", Type::Extended29), 0), {Rule::UnknownId},
          "unknown extended alias neither uses nor changes standard payload state");
    rules(detector.process(frame(8, {8, 9}, 0x100, "vcan0", Type::Extended29), 0), {Rule::UnknownId},
          "unknown alias creates no replay or timestamp history");
    rules(detector.process(frame(0, {3, 4}, 0x200), 0), {Rule::UnknownId}, "standard alias of an extended baseline is also unknown");
    single(detector.process(frame(10002, {1, 2}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=3 threshold=1", "unknown traffic did not replace known payload or increment its count");
}

void test_rejected_input_preserves_payload_state() {
    cansec::Detector detector(policy(1));
    detector.process(frame(100, {1, 2}), 0);
    invalid([&] { detector.process(frame(99, {8, 9}), 0); }, "backwards changed payload is rejected before replay mutation");
    single(detector.process(frame(101, {1, 2}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=2 threshold=1", "backwards record did not reset or increment the run");
    auto bad = frame(110, {8, 9});
    bad.dlc = 9;
    invalid([&] { detector.process(bad, 0); }, "invalid DLC rejected before payload copy");
    single(detector.process(frame(102, {1, 2}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=3 threshold=1", "invalid DLC preserved previous time, payload and count");
    bad = frame(120, {8, 9});
    bad.id_type = static_cast<Type>(99);
    invalid([&] { detector.process(bad, 0); }, "invalid ID type rejected before payload history");
    single(detector.process(frame(103, {1, 2}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=4 threshold=1", "invalid ID type did not change known replay count");
    cansec::Detector first_invalid(policy(1));
    bad = frame(100, {8, 9});
    bad.dlc = 255;
    invalid([&] { first_invalid.process(bad, 0); }, "invalid first payload is rejected");
    rules(first_invalid.process(frame(0, {1, 2}), 0), {}, "first valid payload after rejection still starts at run one");
    single(first_invalid.process(frame(0, {1, 2}), 0), Rule::ReplayBurst, Level::High,
           "identical_payload_run=2 threshold=1", "same-time valid frames still count after initial rejection");
    invalid([] { cansec::Detector detector(policy(0)); }, "constructor rejects zero max identical run");
    invalid([] { cansec::Detector detector(policy(-1)); }, "constructor rejects negative max identical run");
    cansec::Detector largest(policy(std::numeric_limits<int>::max()));
    largest.process(frame(0, {1, 2}), 0);
    rules(largest.process(frame(0, {1, 2}), 0), {}, "maximum valid integer threshold remains positive and is not exceeded early");
}

void test_fixed_replay_combination_and_ownership() {
    auto baseline = policy(1);
    baseline.entries[0].fixed_mask[0] = 0xFF;
    baseline.entries[0].fixed_value[0] = 0xAA;
    cansec::Detector detector(baseline);
    baseline.entries[0].ignore_mask.fill(0xFF);
    baseline.entries[0].max_identical_payload_run = 100;
    rules(detector.process(frame(0, {0xAB, 0xCC}), 0), {Rule::FixedByteViolation},
          "detector owns fixed policy despite caller changing ignore mask");
    const auto both = detector.process(frame(1, {0xAB, 0xCC}), 10);
    rules(both, {Rule::FixedByteViolation, Rule::ReplayBurst}, "fixed violations also update replay runs under the owned threshold");
    check(both.size() == 2 && both[0].severity == Level::Medium && both[1].severity == Level::High &&
              both[1].detail == "identical_payload_run=2 threshold=1", "simultaneous fixed/replay alert severities and count are correct");
    rules(detector.process(frame(2, {0xAC, 0xCC}), 0), {Rule::FixedByteViolation},
          "changed fixed-violating payload resets the replay run");

    baseline = policy(1);
    auto& entry = baseline.entries[0];
    entry.id_type = Type::Extended29;
    entry.periodic = true;
    entry.period_min_us = 8000;
    entry.period_max_us = 12000;
    entry.rate_limit_100ms = 1;
    entry.fixed_mask[0] = 0xFF;
    entry.fixed_value[0] = 0xAA;
    cansec::Detector all(baseline);
    rules(all.process(frame(0, {0xBB, 0xCC, 0xDD}, 0x100, "vcan-payload", Type::Extended29), 1),
          {Rule::DlcMismatch, Rule::FixedByteViolation}, "first DLC/fixed-violating frame is accepted into all histories");
    const auto alerts = all.process(frame(7999, {0xBB, 0xCC, 0xDD}, 0x100, "vcan-payload", Type::Extended29), 9000);
    rules(alerts, {Rule::DlcMismatch, Rule::PeriodViolation, Rule::RateSpike, Rule::FixedByteViolation, Rule::ReplayBurst},
          "combined known-frame alerts follow identity-period-rate-fixed-replay order");
    if (alerts.size() == 5) {
        const std::array<Level, 5> severity{Level::High, Level::Medium, Level::High, Level::Medium, Level::High};
        bool preserved = true;
        for (std::size_t i = 0; i < alerts.size(); ++i) {
            const auto& alert = alerts[i];
            preserved = preserved && alert.severity == severity[i] && alert.capture_ts_us == 7999 &&
                alert.alert_ts_us == 9000 && alert.interface_name == "vcan-payload" && alert.can_id == 0x100 &&
                alert.id_type == Type::Extended29 && alert.dlc == 3 &&
                alert.data == std::array<uint8_t, 8>{0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0};
        }
        check(preserved, "all combined alerts preserve typed fields/severity and omit buffer tail");
        check(alerts[0].detail == "observed_dlc=3 allowed_dlc=2" &&
                  alerts[1].detail == "delta_us=7999 allowed_min_us=8000 allowed_max_us=12000" &&
                  alerts[2].detail == "count_100ms=2 threshold=1" &&
                  alerts[3].detail == "fixed_byte_mismatches=[index=0 observed=0xBB expected=0xAA effective_mask=0xFF]" &&
                  alerts[4].detail == "identical_payload_run=2 threshold=1", "all combined alert details retain exact measurements");
    }
    rules(all.process(frame(1, {0xBB, 0xCC, 0xDD}, 0x555, "vcan-payload", Type::Extended29), 1),
          {Rule::UnknownId}, "unknown ID emits only identity alert even when other policies would fail");
}

}  // namespace

int main() {
    try {
        test_fixed_masks();
        test_present_bytes_only();
        test_replay_threshold_and_reset();
        test_dlc_and_raw_payload_equality();
        test_interleaved_streams();
        test_rejected_input_preserves_payload_state();
        test_fixed_replay_combination_and_ownership();
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] unexpected test exception: " << error.what() << '\n';
        ++failures;
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "test_detector_payload passed.\n";
    return 0;
}
