#include "cansec/report.hpp"

#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace cansec {
namespace {

constexpr std::array<const char*, 6> rule_names = {
    "UNKNOWN_ID", "DLC_MISMATCH", "PERIOD_VIOLATION", "RATE_SPIKE",
    "FIXED_BYTE_VIOLATION", "REPLAY_BURST"
};
constexpr std::array<const char*, 3> severity_names = {"LOW", "MEDIUM", "HIGH"};
constexpr std::array<std::size_t, 6> default_severities = {2, 2, 1, 2, 1, 2};
constexpr std::array<const char*, 6> rule_interpretations = {
    "frames used an ID type and numeric ID absent from the loaded baseline.",
    "frames used a payload length outside the registered ID's allowed lengths.",
    "same-ID arrival intervals fell outside the loaded period bounds.",
    "per-ID frame counts in the 100 ms window exceeded the loaded limit.",
    "payload bits selected by the fixed-byte rule differed from the baseline.",
    "consecutive same-ID frames with identical length and payload exceeded the run limit."
};

std::size_t rule_index(AlertRule rule) {
    switch (rule) {
        case AlertRule::UnknownId: return 0;
        case AlertRule::DlcMismatch: return 1;
        case AlertRule::PeriodViolation: return 2;
        case AlertRule::RateSpike: return 3;
        case AlertRule::FixedByteViolation: return 4;
        case AlertRule::ReplayBurst: return 5;
    }
    throw std::invalid_argument("invalid report alert rule");
}

std::size_t severity_index(Severity severity) {
    switch (severity) {
        case Severity::Low: return 0;
        case Severity::Medium: return 1;
        case Severity::High: return 2;
    }
    throw std::invalid_argument("invalid report alert severity");
}

void validate_frame_fields(IdType id_type, uint32_t can_id, uint8_t dlc) {
    if (id_type != IdType::Standard11 && id_type != IdType::Extended29) {
        throw std::invalid_argument("invalid report CAN ID type");
    }
    const uint32_t maximum = id_type == IdType::Standard11 ? 0x7FFU : 0x1FFFFFFFU;
    if (can_id > maximum || dlc > 8) {
        throw std::invalid_argument("invalid report CAN ID or DLC");
    }
}

// All externally supplied strings are plain text, including inside tables.
// Numeric entities keep Markdown delimiters inert. Newlines and controls are
// shown as visible escape sequences so they cannot add report rows or headings.
std::string markdown_text(const std::string& value) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (std::size_t i = 0; i < value.size();) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (c < 0x80) {
            switch (c) {
                case '&': result += "&amp;"; break;
                case '<': result += "&lt;"; break;
                case '>': result += "&gt;"; break;
                case '|': result += "&#124;"; break;
                case '`': result += "&#96;"; break;
                case '\\': result += "&#92;"; break;
                case '*': result += "&#42;"; break;
                case '_': result += "&#95;"; break;
                case '[': result += "&#91;"; break;
                case ']': result += "&#93;"; break;
                case '#': result += "&#35;"; break;
                case '!': result += "&#33;"; break;
                case '"': result += "&quot;"; break;
                case '\'': result += "&#39;"; break;
                case '\n': result += "&#92;n"; break;
                case '\r': result += "&#92;r"; break;
                case '\t': result += "&#92;t"; break;
                default:
                    if (c < 0x20 || c == 0x7F) {
                        result += "&#92;x";
                        result += hex[c >> 4];
                        result += hex[c & 0x0F];
                    } else {
                        result += static_cast<char>(c);
                    }
            }
            ++i;
            continue;
        }

        const std::size_t length = c >= 0xC2 && c <= 0xDF ? 2 :
                                   c >= 0xE0 && c <= 0xEF ? 3 :
                                   c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        if (length == 0 || value.size() - i < length) {
            throw std::invalid_argument("report string is not valid UTF-8");
        }
        uint32_t codepoint = c & (length == 2 ? 0x1FU : length == 3 ? 0x0FU : 0x07U);
        for (std::size_t j = 1; j < length; ++j) {
            const auto next = static_cast<unsigned char>(value[i + j]);
            if ((next & 0xC0U) != 0x80U) {
                throw std::invalid_argument("report string is not valid UTF-8");
            }
            codepoint = (codepoint << 6) | (next & 0x3FU);
        }
        const uint32_t minimum = length == 2 ? 0x80U : length == 3 ? 0x800U : 0x10000U;
        if (codepoint < minimum || codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            throw std::invalid_argument("report string is not valid UTF-8");
        }
        result.append(value, i, length);
        i += length;
    }
    return result;
}

std::string value_or_na(const std::string& value) {
    return value.empty() ? "N/A" : markdown_text(value);
}

uint64_t rule_total(const std::array<uint64_t, 3>& counts) {
    return counts[0] + counts[1] + counts[2];
}

std::string severity_label(const std::array<uint64_t, 3>& counts,
                           std::size_t default_severity) {
    std::string label;
    for (std::size_t severity = 0; severity < counts.size(); ++severity) {
        if (counts[severity] == 0) continue;
        if (!label.empty()) label += ", ";
        label += severity_names[severity];
    }
    return label.empty() ? severity_names[default_severity] : label;
}

std::string can_id_text(uint32_t can_id) {
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "0x" << std::uppercase << std::hex << can_id;
    return output.str();
}

}  // namespace

void DetectionReport::observe(const CanFrameRecord& frame,
                               const std::vector<Alert>& alerts) {
    validate_frame_fields(frame.id_type, frame.can_id, frame.dlc);
    if (processed_frames_ == std::numeric_limits<uint64_t>::max() ||
        alerts.size() > std::numeric_limits<uint64_t>::max() - alert_count_) {
        throw std::overflow_error("report counter overflow");
    }
    // Validate the entire batch before changing any counters. Each rule or
    // severity subtotal is bounded by the already checked total alert count.
    for (const auto& alert : alerts) {
        validate_frame_fields(alert.id_type, alert.can_id, alert.dlc);
        (void)rule_index(alert.rule);
        (void)severity_index(alert.severity);
    }

    unique_ids_.emplace(frame.id_type, frame.can_id);
    if (processed_frames_ == 0) first_frame_timestamp_ = frame.timestamp_us;
    last_frame_timestamp_ = frame.timestamp_us;
    ++processed_frames_;
    alert_count_ += static_cast<uint64_t>(alerts.size());
    for (const auto& alert : alerts) {
        ++rule_severity_counts_[rule_index(alert.rule)][severity_index(alert.severity)];
        if (first_alert_count_ < first_alerts_.size()) {
            first_alerts_[first_alert_count_++] = alert;
        }
    }
}

std::string format_detection_report(const ReportMetadata& metadata,
                                    const DetectionReport& report) {
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "# CANSecLab-Low Detection Report\n\n## Run Metadata\n\n";
    const auto item = [&](const char* label, const std::string& value) {
        output << "- " << label << ": " << value_or_na(value) << '\n';
    };
    output << "- Run time: " << value_or_na(metadata.started_utc) << " to "
           << value_or_na(metadata.finished_utc) << '\n';
    item("Started UTC", metadata.started_utc);
    item("Finished UTC", metadata.finished_utc);
    output << "- Elapsed steady-clock time (us): " << metadata.elapsed_us << '\n';
    item("Mode", metadata.mode);
    item("Termination reason", metadata.termination_reason);
    item("Git commit", metadata.git_commit);
    item("Source SHA256", metadata.source_sha256);
    item("Build type", metadata.build_type);
    item("Compiler", metadata.compiler);
    item("OS", metadata.os);
    item("Kernel", metadata.kernel);
    item("Interface", metadata.interface_name);
    item("Rules file", metadata.rules_path);
    item("Rules SHA256", metadata.rules_sha256);
    if (metadata.mode == "live" && metadata.input_path.empty()) {
        output << "- Input file: N/A (live SocketCAN has no source input file)\n";
    } else {
        item("Input file", metadata.input_path);
    }
    if (metadata.mode == "live" && metadata.input_sha256.empty() && metadata.input_path.empty()) {
        output << "- Input SHA256: N/A (live SocketCAN has no source input file)\n";
    } else {
        item("Input SHA256", metadata.input_sha256);
    }
    if (metadata.mode == "offline" && metadata.alerts_path.empty()) {
        output << "- Alerts JSONL file: N/A (offline check-log does not produce an alert JSONL file)\n";
    } else {
        item("Alerts JSONL file", metadata.alerts_path);
    }
    if (metadata.mode == "offline" && metadata.alerts_path.empty() && metadata.alerts_sha256.empty()) {
        output << "- Alerts JSONL SHA256: N/A (offline check-log does not produce an alert JSONL file)\n";
    } else {
        item("Alerts JSONL SHA256", metadata.alerts_sha256);
    }
    item("Command line", metadata.command_line);
    output << "- max_frames: " << metadata.max_frames << " (0 means unlimited)\n"
           << "- max_seconds: " << metadata.max_seconds << " (0 means unlimited)\n\n"
           << "Source SHA256 identifies the configured source snapshot; it is not a Git commit. "
              "File hashes identify the supplied rules, optional input log, and saved alert JSONL.\n\n";

    output << "## Input Summary\n\n"
           << "- Total frames processed: " << report.processed_frames_ << '\n'
           << "- Unique CAN IDs observed: " << report.unique_ids_.size() << '\n'
           << "- First frame timestamp: ";
    if (report.processed_frames_ == 0) output << "N/A\n";
    else output << report.first_frame_timestamp_ << '\n';
    output << "- Last frame timestamp: ";
    if (report.processed_frames_ == 0) output << "N/A\n";
    else output << report.last_frame_timestamp_ << '\n';
    output << "\nTimestamps are capture_ts_us values in microseconds, in frame processing order. "
              "Standard and extended IDs with the same numeric value count as different IDs.\n\n";

    output << "## Alert Summary\n\n- Total alerts: " << report.alert_count_ << "\n\n"
           << "| Rule | Severity | Count |\n|---|---|---:|\n";
    std::array<uint64_t, 3> severity_totals{};
    for (std::size_t rule = 0; rule < rule_names.size(); ++rule) {
        const auto& counts = report.rule_severity_counts_[rule];
        output << "| " << rule_names[rule] << " | "
               << severity_label(counts, default_severities[rule]) << " | "
               << rule_total(counts) << " |\n";
        for (std::size_t severity = 0; severity < counts.size(); ++severity) {
            severity_totals[severity] += counts[severity];
        }
    }
    output << "\nCounts refer to alert records, not distinct frames. One frame may trigger several rules. "
              "Zero-count rows show the current detector's default severity; nonzero rows show observed severities.\n\n"
           << "| Severity | Count |\n|---|---:|\n";
    for (std::size_t severity = 0; severity < severity_totals.size(); ++severity) {
        output << "| " << severity_names[severity] << " | " << severity_totals[severity] << " |\n";
    }

    output << "\n## First Alerts\n\n"
           << "First " << report.first_alert_count_ << " of " << report.alert_count_
           << " alerts in processing order (at most 10 are retained).\n\n"
           << "| capture_ts_us | alert_ts_us | id_type | CAN ID | Rule | Severity | Detail |\n"
           << "|---:|---:|---|---|---|---|---|\n";
    for (std::size_t i = 0; i < report.first_alert_count_; ++i) {
        const auto& alert = report.first_alerts_[i];
        output << "| " << alert.capture_ts_us << " | " << alert.alert_ts_us << " | "
               << (alert.id_type == IdType::Standard11 ? "standard" : "extended")
               << " | " << can_id_text(alert.can_id) << " | " << rule_names[rule_index(alert.rule)]
               << " | " << severity_names[severity_index(alert.severity)] << " | "
               << markdown_text(alert.detail) << " |\n";
    }
    if (report.first_alert_count_ == 0) output << "\nNo alert examples.\n";

    output << "\n## Interpretation\n\n";
    if (report.processed_frames_ == 0) {
        output << "No frames were processed. Zero alerts here says nothing about the traffic.\n";
    } else if (report.alert_count_ == 0) {
        output << report.processed_frames_ << " frames were checked against the loaded rules and no rule violations were observed.\n";
    } else {
        output << report.processed_frames_ << " processed frames produced " << report.alert_count_
               << " rule-violation alerts. The counts do not establish an attack or identify its cause.\n\n";
        for (std::size_t rule = 0; rule < rule_names.size(); ++rule) {
            const auto count = rule_total(report.rule_severity_counts_[rule]);
            if (count != 0) {
                output << "- " << rule_names[rule] << " (" << count << " alerts): "
                       << rule_interpretations[rule] << '\n';
            }
        }
    }

    output << "\n## Limitations\n\n"
           << "- Classical CAN only (payload up to 8 bytes). CAN FD is not supported.\n"
           << "- Tested with synthetic traffic and Linux vcan, not on a real vehicle.\n"
           << "- A rule violation is not proof of an attack, and zero alerts is not proof of safety.\n"
           << "- Live timestamps come from per-packet kernel receive metadata (SO_TIMESTAMPNS, or SO_TIMESTAMP as a fallback), "
              "truncated to microseconds. Missing metadata fails the read.\n"
           << "- alert_ts_us is taken right after the rule checks, so alert_ts_us - capture_ts_us is not an end-to-end latency. "
              "Offline log processing time is not live CAN latency.\n"
           << "- The first-alert table keeps at most 10 examples. All alerts are in the JSONL file (live) or on stdout (offline).\n";
    return output.str();
}

}  // namespace cansec
