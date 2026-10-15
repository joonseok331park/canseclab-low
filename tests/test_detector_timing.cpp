#include "cansec/detector.hpp"

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

void check(bool condition, const std::string& name) {
    std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!condition) {
        ++failures;
    }
}

cansec::DetectionBaseline policy(bool periodic = true, int rate = 100,
                                 uint64_t minimum = 8000, uint64_t maximum = 12000) {
    cansec::IdProfile entry;
    entry.can_id = 0x100;
    entry.id_type = cansec::IdType::Standard11;
    entry.allowed_dlc = {2};
    entry.periodic = periodic;
    entry.period_min_us = periodic ? minimum : 0;
    entry.period_max_us = periodic ? maximum : 0;
    entry.rate_limit_100ms = rate;
    entry.max_identical_payload_run = 100;
    cansec::DetectionBaseline baseline;
    baseline.entries.push_back(entry);
    return baseline;
}

cansec::CanFrameRecord frame(uint64_t timestamp, uint32_t id = 0x100,
                             const std::string& interface = "vcan0", uint8_t dlc = 2,
                             cansec::IdType type = cansec::IdType::Standard11) {
    cansec::CanFrameRecord record;
    record.timestamp_us = timestamp;
    record.can_id = id;
    record.id_type = type;
    record.interface_name = interface;
    record.dlc = dlc;
    record.data = {0xAA, 0xBB, 0xCC, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};
    return record;
}

void rules(const std::vector<cansec::Alert>& alerts, std::initializer_list<Rule> expected,
           const std::string& name) {
    bool match = alerts.size() == expected.size();
    std::size_t index = 0;
    for (const auto rule : expected) {
        if (index >= alerts.size() || alerts[index].rule != rule) {
            match = false;
        }
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
        check(false, name + " raised a different exception: " + error.what());
    }
}

void test_period() {
    cansec::Detector zero_start(policy());
    rules(zero_start.process(frame(0), 50), {}, "first known frame does not have a period comparison");
    rules(zero_start.process(frame(8000), 50), {}, "timestamp zero is retained as previous arrival");

    for (const uint64_t delta : {0ULL, 7999ULL, 8000ULL, 12000ULL, 12001ULL}) {
        cansec::Detector detector(policy());
        detector.process(frame(100000), 0);
        const auto alerts = detector.process(frame(100000 + delta), 55);
        if (delta >= 8000 && delta <= 12000) {
            rules(alerts, {}, "inclusive period boundary delta=" + std::to_string(delta));
        } else {
            single(alerts, Rule::PeriodViolation, Level::Medium,
                   "delta_us=" + std::to_string(delta) + " allowed_min_us=8000 allowed_max_us=12000",
                   "period violation severity/detail delta=" + std::to_string(delta));
        }
    }
    cansec::Detector recovery(policy());
    recovery.process(frame(0), 0);
    rules(recovery.process(frame(7999), 0), {Rule::PeriodViolation}, "short arrival produces period alert");
    rules(recovery.process(frame(17999), 0), {}, "violating arrival becomes the next period reference");

    cansec::Detector nonperiodic(policy(false));
    rules(nonperiodic.process(frame(0), 0), {}, "nonperiodic first frame accepted");
    rules(nonperiodic.process(frame(0), 0), {}, "nonperiodic same timestamp has no period alert");
    rules(nonperiodic.process(frame(5000000), 0), {}, "nonperiodic long gap has no period alert");
    cansec::Detector zero_range(policy(true, 100, 0, 0));
    zero_range.process(frame(10), 0);
    rules(zero_range.process(frame(10), 0), {}, "zero period is allowed when policy permits zero");
    single(zero_range.process(frame(11), 0), Rule::PeriodViolation, Level::Medium,
           "delta_us=1 allowed_min_us=0 allowed_max_us=0", "zero-range policy rejects a positive delta");
}

void test_rate() {
    cansec::Detector detector(policy(false, 2));
    rules(detector.process(frame(0), 0), {}, "rate count includes first frame without exceeding two");
    rules(detector.process(frame(1000), 0), {}, "rate count exactly at threshold is allowed");
    single(detector.process(frame(2000), 0), Rule::RateSpike, Level::High,
           "count_100ms=3 threshold=2", "current frame makes count exceed threshold");
    single(detector.process(frame(3000), 0), Rule::RateSpike, Level::High,
           "count_100ms=4 threshold=2", "continued excess generates another rate alert");
    rules(detector.process(frame(103000), 0), {}, "expiration of all old arrivals restores normal rate");
    rules(detector.process(frame(103000), 0), {}, "recovered window retains its current frame");
    single(detector.process(frame(103000), 0), Rule::RateSpike, Level::High,
           "count_100ms=3 threshold=2", "same-time frames are counted independently");

    cansec::Detector just_inside(policy(false, 1));
    just_inside.process(frame(0), 0);
    single(just_inside.process(frame(99999), 0), Rule::RateSpike, Level::High,
           "count_100ms=2 threshold=1", "arrival 99999us old remains inside the window");
    cansec::Detector exact_boundary(policy(false, 1));
    exact_boundary.process(frame(0), 0);
    rules(exact_boundary.process(frame(100000), 0), {}, "arrival exactly 100000us old is excluded");
    single(exact_boundary.process(frame(100001), 0), Rule::RateSpike, Level::High,
           "count_100ms=2 threshold=1", "new arrival after expiration still counts in the next window");

    cansec::Detector partial(policy(false, 2));
    partial.process(frame(0), 0);
    partial.process(frame(10), 0);
    partial.process(frame(20), 0);
    single(partial.process(frame(100000), 0), Rule::RateSpike, Level::High,
           "count_100ms=3 threshold=2", "partial expiration keeps arrivals that remain inside the window");
    rules(partial.process(frame(100020), 0), {}, "partial expiration can restore exactly the allowed count");
}

void test_isolation() {
    auto baseline = policy();
    auto other = baseline.entries[0];
    other.can_id = 0x200;
    baseline.entries.push_back(other);
    cansec::Detector periods(baseline);
    periods.process(frame(100000), 0);
    rules(periods.process(frame(1000, 0x200), 0), {}, "another ID may begin at a smaller timestamp");
    rules(periods.process(frame(10, 0x100, "vcan1"), 0), {}, "another interface may begin at a smaller timestamp");
    rules(periods.process(frame(110000), 0), {}, "first ID retains its own period history");
    rules(periods.process(frame(11000, 0x200), 0), {}, "second ID retains its own period history");
    rules(periods.process(frame(10010, 0x100, "vcan1"), 0), {}, "second interface retains its own period history");
    rules(periods.process(frame(0, 0x100, "vcan0", 2, cansec::IdType::Extended29), 0),
          {Rule::UnknownId}, "different ID type is unknown and cannot change the standard history");
    rules(periods.process(frame(120000), 0), {}, "unknown typed identity did not alter known history");

    baseline = policy(false, 1);
    other = baseline.entries[0];
    other.can_id = 0x200;
    baseline.entries.push_back(other);
    cansec::Detector rates(baseline);
    rules(rates.process(frame(0), 0), {}, "first ID starts an independent rate window");
    rules(rates.process(frame(0, 0x200), 0), {}, "second ID is not charged for the first ID");
    rules(rates.process(frame(0, 0x100, "vcan1"), 0), {}, "second interface is not charged for the first bus");
    single(rates.process(frame(0), 0), Rule::RateSpike, Level::High,
           "count_100ms=2 threshold=1", "first ID only counts its own arrivals");
    single(rates.process(frame(0, 0x200), 0), Rule::RateSpike, Level::High,
           "count_100ms=2 threshold=1", "second ID only counts its own arrivals");
    single(rates.process(frame(0, 0x100, "vcan1"), 0), Rule::RateSpike, Level::High,
           "count_100ms=2 threshold=1", "second interface only counts its own arrivals");
    rules(rates.process(frame(5, 0x555, "vcan0", 8), 0), {Rule::UnknownId}, "unknown identity gets no rate alert");
    rules(rates.process(frame(4, 0x555, "vcan0", 8), 0), {Rule::UnknownId}, "unknown identity creates no ordered timestamp state");
}

void test_combined_alerts_and_fields() {
    auto baseline = policy(true, 1);
    baseline.entries[0].id_type = cansec::IdType::Extended29;
    cansec::Detector detector(baseline);
    detector.process(frame(0, 0x100, "vcan-test", 2, cansec::IdType::Extended29), 1);
    const auto observed = frame(7999, 0x100, "vcan-test", 3, cansec::IdType::Extended29);
    const auto alerts = detector.process(observed, 12345000);
    rules(alerts, {Rule::DlcMismatch, Rule::PeriodViolation, Rule::RateSpike},
          "DLC, period and rate violations appear in identity-period-rate order");
    if (alerts.size() == 3) {
        check(alerts[0].severity == Level::High && alerts[1].severity == Level::Medium &&
                  alerts[2].severity == Level::High, "combined alerts use specified severity levels");
        check(alerts[0].detail == "observed_dlc=3 allowed_dlc=2" &&
                  alerts[1].detail == "delta_us=7999 allowed_min_us=8000 allowed_max_us=12000" &&
                  alerts[2].detail == "count_100ms=2 threshold=1", "combined alerts contain exact measured details");
        bool preserved = true;
        for (const auto& alert : alerts) {
            preserved = preserved && alert.capture_ts_us == 7999 && alert.alert_ts_us == 12345000 &&
                alert.interface_name == "vcan-test" && alert.can_id == 0x100 &&
                alert.id_type == cansec::IdType::Extended29 && alert.dlc == 3 &&
                alert.data == std::array<uint8_t, 8>{0xAA, 0xBB, 0xCC, 0, 0, 0, 0, 0};
        }
        check(preserved, "all rule alerts preserve fields and zero bytes beyond DLC");
    }
    single(detector.process(frame(17999, 0x100, "vcan-test", 2, cansec::IdType::Extended29), 2),
           Rule::RateSpike, Level::High, "count_100ms=3 threshold=1",
           "DLC-mismatched frame updates both period reference and rate count");

    auto original = policy(true, 1);
    cansec::Detector owned(original);
    original.entries[0].can_id = 0x555;
    original.entries[0].allowed_dlc = {8};
    original.entries[0].periodic = false;
    original.entries[0].rate_limit_100ms = 100;
    rules(owned.process(frame(0), 0), {}, "detector owns baseline identity and DLC policy");
    rules(owned.process(frame(7999), 0), {Rule::PeriodViolation, Rule::RateSpike},
          "caller baseline edits cannot change owned timing policy");
}

void test_invalid_and_out_of_order() {
    cansec::Detector ordered(policy(true, 3));
    ordered.process(frame(100000), 0);
    ordered.process(frame(110000), 0);
    invalid([&] { ordered.process(frame(105000, 0x100, "vcan0", 3), 0); },
            "decreasing known timestamp is rejected even with wrong DLC");
    rules(ordered.process(frame(120000), 0), {}, "rejected timestamp changes neither previous arrival nor rate queue");
    single(ordered.process(frame(130000), 0), Rule::RateSpike, Level::High,
           "count_100ms=4 threshold=3", "valid history continues after a rejected timestamp");

    cansec::Detector nonperiodic(policy(false, 2));
    nonperiodic.process(frame(1000), 0);
    invalid([&] { nonperiodic.process(frame(999), 0); }, "nonperiodic keys also reject decreasing timestamps");
    rules(nonperiodic.process(frame(1001), 0), {}, "nonperiodic rejected timestamp leaves rate count unchanged");

    for (int kind = 0; kind < 4; ++kind) {
        cansec::Detector detector(policy(true, 2));
        detector.process(frame(100000), 0);
        auto bad = frame(105000);
        if (kind == 0) bad.dlc = 9;
        if (kind == 1) bad.id_type = static_cast<cansec::IdType>(99);
        if (kind == 2) bad.can_id = 0x800;
        if (kind == 3) { bad.id_type = cansec::IdType::Extended29; bad.can_id = 0x20000000; }
        invalid([&] { detector.process(bad, 0); }, "invalid record kind=" + std::to_string(kind));
        rules(detector.process(frame(110000), 0), {}, "invalid record preserved timing state kind=" + std::to_string(kind));
    }
    cansec::Detector first_invalid(policy());
    invalid([&] { first_invalid.process(frame(100000, 0x100, "vcan0", 9), 0); }, "invalid first frame is rejected");
    rules(first_invalid.process(frame(1), 0), {}, "invalid first frame creates no history");
    auto bad_window = policy();
    bad_window.window_ms = 200;
    invalid([&] { cansec::Detector detector(bad_window); }, "constructor rejects a non-100ms window");
    invalid([] { cansec::Detector detector(policy(false, 0)); }, "constructor rejects a zero rate threshold");
    invalid([] { cansec::Detector detector(policy(false, -1)); }, "constructor rejects a negative rate threshold");
}

void test_uint64_boundaries() {
    const auto maximum = std::numeric_limits<uint64_t>::max();
    cansec::Detector near_max(policy(true, 3));
    rules(near_max.process(frame(maximum - 20000), maximum), {}, "first near-UINT64_MAX timestamp is accepted");
    rules(near_max.process(frame(maximum - 10000), maximum), {}, "near-UINT64_MAX period subtraction is exact");
    rules(near_max.process(frame(maximum), maximum), {}, "UINT64_MAX arrival preserves allowed delta and rate");
    rules(near_max.process(frame(maximum), maximum), {Rule::PeriodViolation, Rule::RateSpike},
          "equal UINT64_MAX timestamps use zero delta and increment count without overflow");

    cansec::Detector expires(policy(false, 1));
    expires.process(frame(maximum - 100000), 0);
    rules(expires.process(frame(maximum), 0), {}, "exact rate-window expiry works near UINT64_MAX");
    cansec::Detector inside(policy(false, 1));
    inside.process(frame(maximum - 99999), 0);
    single(inside.process(frame(maximum), 0), Rule::RateSpike, Level::High,
           "count_100ms=2 threshold=1", "99999us inclusion works near UINT64_MAX");
    cansec::Detector widest(policy(true, 1, 0, maximum));
    widest.process(frame(0), 0);
    rules(widest.process(frame(maximum), 0), {}, "full uint64 delta is allowed and safely expires old rate history");
}

}  // namespace

int main() {
    try {
        test_period();
        test_rate();
        test_isolation();
        test_combined_alerts_and_fields();
        test_invalid_and_out_of_order();
        test_uint64_boundaries();
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] unexpected test exception: " << error.what() << '\n';
        ++failures;
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "test_detector_timing passed.\n";
    return 0;
}
