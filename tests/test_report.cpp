#include "cansec/report.hpp"

#include <array>
#include <iostream>
#include <limits>
#include <locale>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int failures = 0;
int checks = 0;

void check(bool result, const std::string& name) {
    ++checks;
    std::cout << (result ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!result) ++failures;
}

bool contains(const std::string& text, const std::string& part) {
    return text.find(part) != std::string::npos;
}

template <typename Action>
void invalid(Action action, const std::string& name) {
    try {
        action();
        check(false, name);
    } catch (const std::invalid_argument&) {
        check(true, name);
    }
}

cansec::CanFrameRecord frame(uint64_t timestamp = 0,
                             cansec::IdType type = cansec::IdType::Standard11,
                             uint32_t id = 0x123) {
    cansec::CanFrameRecord result;
    result.timestamp_us = timestamp;
    result.interface_name = "vcan0";
    result.id_type = type;
    result.can_id = id;
    result.dlc = 2;
    result.data = {0xAA, 0x10};
    return result;
}

cansec::Alert alert(const cansec::CanFrameRecord& input,
                    cansec::AlertRule rule = cansec::AlertRule::UnknownId,
                    cansec::Severity severity = cansec::Severity::High,
                    const std::string& detail = "observed") {
    cansec::Alert result;
    result.capture_ts_us = input.timestamp_us;
    result.alert_ts_us = input.timestamp_us;
    result.interface_name = input.interface_name;
    result.id_type = input.id_type;
    result.can_id = input.can_id;
    result.dlc = input.dlc;
    result.data = input.data;
    result.rule = rule;
    result.severity = severity;
    result.detail = detail;
    return result;
}

cansec::ReportMetadata metadata() {
    cansec::ReportMetadata result;
    result.started_utc = "2026-10-15T03:00:00Z";
    result.finished_utc = "2026-10-15T03:00:01Z";
    result.termination_reason = "max_frames";
    result.mode = "live";
    result.git_commit = "N/A";
    result.source_sha256 = std::string(64, 'a');
    result.build_type = "Debug";
    result.compiler = "GNU 13.3.0";
    result.os = "Linux";
    result.kernel = "test-kernel";
    result.interface_name = "vcan0";
    result.rules_path = "baseline.ini";
    result.rules_sha256 = std::string(64, 'b');
    result.alerts_path = "alerts.jsonl";
    result.alerts_sha256 = std::string(64, 'c');
    result.command_line = "cansec-detect --if vcan0 --max-frames 3";
    result.elapsed_us = 1234567;
    result.max_frames = 3;
    result.max_seconds = 5;
    return result;
}

struct GroupDigits : std::numpunct<char> {
    char do_thousands_sep() const override { return ','; }
    std::string do_grouping() const override { return "\3"; }
};

}  // namespace

int main() {
    using cansec::AlertRule;
    using cansec::IdType;
    using cansec::Severity;
    auto meta = metadata();
    cansec::DetectionReport empty;
    auto text = cansec::format_detection_report(meta, empty);
    check(empty.processed_frames() == 0 && empty.alert_count() == 0,
          "initial processed and alert counters are separately zero");
    for (const auto* heading : {"# CANSecLab-Low Detection Report", "## Run Metadata",
         "## Input Summary", "## Alert Summary", "## First Alerts", "## Interpretation", "## Limitations"}) {
        check(contains(text, heading), std::string("required heading: ") + heading);
    }
    check(contains(text, "- Total frames processed: 0\n") &&
          contains(text, "- Unique CAN IDs observed: 0\n") &&
          contains(text, "- Total alerts: 0\n"), "empty run shows zero counters");
    check(contains(text, "- First frame timestamp: N/A\n") &&
          contains(text, "- Last frame timestamp: N/A\n"), "empty run timestamps are N/A rather than epoch zero");
    check(contains(text, "No frames were processed.") && contains(text, "No alert examples."),
          "empty run interpretation does not imply checked traffic");
    constexpr std::array<const char*, 6> rule_names = {"UNKNOWN_ID", "DLC_MISMATCH",
        "PERIOD_VIOLATION", "RATE_SPIKE", "FIXED_BYTE_VIOLATION", "REPLAY_BURST"};
    constexpr std::array<const char*, 6> severity_names = {"HIGH", "HIGH", "MEDIUM", "HIGH", "MEDIUM", "HIGH"};
    for (std::size_t i = 0; i < rule_names.size(); ++i) {
        check(contains(text, std::string("| ") + rule_names[i] + " | " + severity_names[i] + " | 0 |"),
              std::string("zero-count row uses actual detector severity: ") + rule_names[i]);
    }
    check(contains(text, "- Source SHA256: " + std::string(64, 'a')) &&
          contains(text, "- Rules SHA256: " + std::string(64, 'b')) &&
          contains(text, "- Alerts JSONL SHA256: " + std::string(64, 'c')),
          "source, rule and output hashes remain distinct metadata");
    check(contains(text, "it is not a Git commit") && contains(text, "- Git commit: N/A\n"),
          "source identifier is not substituted for unavailable Git commit");
    check(contains(text, "- Input SHA256: N/A (live SocketCAN has no source input file)"),
          "live report shows N/A for the input hash");
    check(contains(text, "- Elapsed steady-clock time (us): 1234567\n") &&
          contains(text, "- max_frames: 3 ") && contains(text, "- max_seconds: 5 "),
          "elapsed duration and configured stop limits are recorded");

    cansec::DetectionReport checked;
    checked.observe(frame(0), {});
    checked.observe(frame(25, IdType::Extended29), {});
    checked.observe(frame(50), {});
    text = cansec::format_detection_report(meta, checked);
    check(checked.processed_frames() == 3 && checked.alert_count() == 0,
          "received frames without warnings are distinct from an empty run");
    check(contains(text, "- Unique CAN IDs observed: 2\n"),
          "same numeric standard and extended IDs remain distinct while repeats deduplicate");
    check(contains(text, "- First frame timestamp: 0\n") &&
          contains(text, "- Last frame timestamp: 50\n"), "zero is a valid actual frame timestamp");
    check(contains(text, "3 frames were checked") && !contains(text, "No frames were processed."),
          "zero-alert interpretation uses checked frame count");

    cansec::DetectionReport all_rules;
    const auto first = frame(100);
    all_rules.observe(first, {alert(first, AlertRule::UnknownId)});
    const auto second = frame(200);
    all_rules.observe(second, {alert(second, AlertRule::DlcMismatch)});
    const auto third = frame(300, IdType::Extended29);
    auto period = alert(third, AlertRule::PeriodViolation, Severity::Medium, "interval_us=2 min_us=9");
    period.alert_ts_us = 345;
    all_rules.observe(third, {period, alert(third, AlertRule::RateSpike),
        alert(third, AlertRule::FixedByteViolation, Severity::Medium), alert(third, AlertRule::ReplayBurst)});
    text = cansec::format_detection_report(meta, all_rules);
    check(all_rules.processed_frames() == 3 && all_rules.alert_count() == 6,
          "multiple alerts per frame are counted without inflating processed frames");
    for (std::size_t i = 0; i < rule_names.size(); ++i) {
        check(contains(text, std::string("| ") + rule_names[i] + " | " + severity_names[i] + " | 1 |"),
              std::string("observed rule count: ") + rule_names[i]);
    }
    check(contains(text, "| LOW | 0 |") && contains(text, "| MEDIUM | 2 |") && contains(text, "| HIGH | 4 |"),
          "severity totals agree with the six actual alerts");
    check(contains(text, "| 300 | 345 | extended | 0x123 | PERIOD_VIOLATION | MEDIUM | interval&#95;us=2 min&#95;us=9 |"),
          "example preserves capture/check timestamps, typed ID, rule, severity and escaped detail");
    check(contains(text, "| 100 | 100 | standard | 0x123 | UNKNOWN_ID | HIGH | observed |"),
          "example retains standard ID with the same numeric value");
    check(contains(text, "3 processed frames produced 6 rule-violation alerts") &&
          contains(text, "The counts do not establish an attack"), "interpretation reports the alert counts");
    check(contains(text, "- REPLAY_BURST (1 alerts): consecutive same-ID frames") &&
          contains(text, "- RATE_SPIKE (1 alerts): per-ID frame counts in the 100 ms window"),
          "rule interpretations distinguish payload runs from rate windows");

    cansec::DetectionReport bounded;
    std::vector<cansec::Alert> batch;
    for (unsigned i = 0; i < 16; ++i) {
        const auto sample = frame(1000 - i);
        batch.push_back(alert(sample, AlertRule::UnknownId, Severity::High,
                              "EXAMPLE" + std::to_string(i) + "Z"));
        if (i == 7 || i == 15) {
            bounded.observe(sample, batch);
            batch.clear();
        }
    }
    text = cansec::format_detection_report(meta, bounded);
    check(bounded.processed_frames() == 2 && bounded.alert_count() == 16 &&
          contains(text, "| UNKNOWN_ID | HIGH | 16 |"), "bounded examples retain full counters across batches");
    check(contains(text, "First 10 of 16 alerts") && contains(text, "EXAMPLE9Z") &&
          !contains(text, "EXAMPLE10Z") && !contains(text, "EXAMPLE15Z"),
          "only the first ten encountered examples are retained");
    check(text.find("EXAMPLE0Z") < text.find("EXAMPLE9Z"),
          "examples preserve observation order even when capture timestamps decrease");

    cansec::DetectionReport mixed;
    mixed.observe(first, {alert(first, AlertRule::UnknownId, Severity::Low),
                          alert(first, AlertRule::UnknownId, Severity::High)});
    text = cansec::format_detection_report(meta, mixed);
    check(contains(text, "| UNKNOWN_ID | LOW, HIGH | 2 |") && contains(text, "| LOW | 1 |"),
          "aggregation reflects actual alert severities instead of relabeling them");

    const std::string hostile = std::string("plain|\n<script>&`[link](target)*_\\\r\t") + u8"한글 😀";
    const std::string escaped = std::string("plain&#124;&#92;n&lt;script&gt;&amp;&#96;&#91;link&#93;(target)&#42;&#95;&#92;&#92;r&#92;t") + u8"한글 😀";
    const std::array<std::string cansec::ReportMetadata::*, 18> fields = {
        &cansec::ReportMetadata::started_utc, &cansec::ReportMetadata::finished_utc,
        &cansec::ReportMetadata::termination_reason, &cansec::ReportMetadata::mode,
        &cansec::ReportMetadata::git_commit, &cansec::ReportMetadata::source_sha256,
        &cansec::ReportMetadata::build_type, &cansec::ReportMetadata::compiler,
        &cansec::ReportMetadata::os, &cansec::ReportMetadata::kernel,
        &cansec::ReportMetadata::interface_name, &cansec::ReportMetadata::rules_path,
        &cansec::ReportMetadata::rules_sha256, &cansec::ReportMetadata::input_path,
        &cansec::ReportMetadata::input_sha256, &cansec::ReportMetadata::alerts_path,
        &cansec::ReportMetadata::alerts_sha256, &cansec::ReportMetadata::command_line
    };
    for (const auto member : fields) {
        auto hostile_meta = metadata();
        hostile_meta.*member = hostile;
        text = cansec::format_detection_report(hostile_meta, empty);
        check(contains(text, escaped) && !contains(text, "<script>") && !contains(text, "plain|\n"),
              "untrusted metadata remains plain text and valid UTF-8");
    }
    cansec::DetectionReport escaped_alert;
    auto hostile_alert = alert(first, AlertRule::RateSpike, Severity::High, hostile);
    escaped_alert.observe(first, {hostile_alert});
    text = cansec::format_detection_report(meta, escaped_alert);
    check(contains(text, "| " + escaped + " |\n") && !contains(text, "<script>"),
          "detail cannot inject a table row, HTML, code span or Markdown link");
    hostile_alert.detail = std::string("nul\0del\x7F", 8);
    cansec::DetectionReport controls;
    controls.observe(first, {hostile_alert});
    text = cansec::format_detection_report(meta, controls);
    check(contains(text, "nul&#92;x00del&#92;x7F") && text.find('\0') == std::string::npos,
          "NUL and DEL are visible escaped text");
    for (const auto& bad : {std::string("\x80"), std::string("\xC0\xAF"),
         std::string("\xE0\x80\x80"), std::string("\xED\xA0\x80"),
         std::string("\xF4\x90\x80\x80"), std::string("\xE2\x82"), std::string("\xC2x")}) {
        auto bad_meta = meta;
        bad_meta.command_line = bad;
        invalid([&] { cansec::format_detection_report(bad_meta, empty); }, "invalid UTF-8 metadata rejected");
    }
    cansec::DetectionReport bad_detail;
    hostile_alert.detail = std::string("\x80");
    bad_detail.observe(first, {hostile_alert});
    invalid([&] { cansec::format_detection_report(meta, bad_detail); }, "invalid UTF-8 detail rejected");

    auto offline = metadata();
    offline.mode = "offline";
    offline.termination_reason = "end_of_log";
    offline.input_path = "input.log";
    offline.input_sha256 = std::string(64, 'd');
    offline.alerts_path.clear();
    offline.alerts_sha256.clear();
    text = cansec::format_detection_report(offline, checked);
    check(contains(text, "- Input file: input.log\n") && contains(text, "- Input SHA256: " + std::string(64, 'd')),
          "offline input path and its hash are included");
    check(contains(text, "- Alerts JSONL SHA256: N/A (offline check-log does not produce an alert JSONL file)"),
          "offline report shows N/A for the JSONL hash");
    check(contains(text, "Offline log processing time is not live CAN latency") &&
          contains(text, "per-packet kernel receive metadata") && contains(text, "Missing metadata fails") &&
          contains(text, "synthetic traffic and Linux vcan"),
          "measurement and validation scope limitations are always present");

    cansec::DetectionReport exact;
    const auto huge = frame(std::numeric_limits<uint64_t>::max());
    exact.observe(huge, {alert(huge)});
    const auto expected = cansec::format_detection_report(meta, exact);
    check(contains(expected, "18446744073709551615"), "uint64 timestamps are printed without floating-point rounding");
    const auto old_locale = std::locale();
    std::locale::global(std::locale(old_locale, new GroupDigits));
    check(cansec::format_detection_report(meta, exact) == expected, "report numbers are independent of global locale");
    std::locale::global(old_locale);

    cansec::DetectionReport valid_before_bad;
    valid_before_bad.observe(first, {});
    auto bad_frame = first;
    bad_frame.dlc = 9;
    invalid([&] { valid_before_bad.observe(bad_frame, {}); }, "invalid frame DLC rejected");
    bad_frame = first;
    bad_frame.can_id = 0x800;
    invalid([&] { valid_before_bad.observe(bad_frame, {}); }, "standard ID overflow rejected");
    bad_frame.id_type = static_cast<IdType>(99);
    invalid([&] { valid_before_bad.observe(bad_frame, {}); }, "invalid frame ID type rejected");
    auto bad_alert = alert(first);
    bad_alert.rule = static_cast<AlertRule>(99);
    invalid([&] { valid_before_bad.observe(first, {alert(first), bad_alert}); }, "invalid batch rule rejected before aggregation");
    bad_alert = alert(first);
    bad_alert.severity = static_cast<Severity>(99);
    invalid([&] { valid_before_bad.observe(first, {bad_alert}); }, "invalid alert severity rejected");
    bad_alert = alert(first);
    bad_alert.id_type = IdType::Extended29;
    bad_alert.can_id = 0x20000000;
    invalid([&] { valid_before_bad.observe(first, {bad_alert}); }, "extended alert ID overflow rejected");
    check(valid_before_bad.processed_frames() == 1 && valid_before_bad.alert_count() == 0,
          "invalid input batches leave existing report counters unchanged");

    std::cout << checks << " checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
