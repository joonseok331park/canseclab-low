#include "cansec/detector.hpp"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace cansec {
namespace {

void validate_record(const CanFrameRecord& record) {
    if (record.id_type != IdType::Standard11 && record.id_type != IdType::Extended29) {
        throw std::invalid_argument("invalid CAN ID type in detector input");
    }
    const uint32_t maximum_id = record.id_type == IdType::Standard11 ? 0x7FFU : 0x1FFFFFFFU;
    if (record.can_id > maximum_id) {
        throw std::invalid_argument("CAN ID exceeds the range of its ID type");
    }
    if (record.dlc > record.data.size()) {
        throw std::invalid_argument("detector input DLC exceeds 8 bytes");
    }
}

const IdProfile* find_profile(const DetectionBaseline& baseline, const CanFrameRecord& record) {
    const auto entry = std::find_if(baseline.entries.begin(), baseline.entries.end(),
        [&record](const IdProfile& profile) {
            return profile.can_id == record.can_id && profile.id_type == record.id_type;
        });
    return entry == baseline.entries.end() ? nullptr : &*entry;
}

Alert make_alert(const CanFrameRecord& record, uint64_t alert_timestamp_us,
                 AlertRule rule, Severity severity, std::string detail) {
    Alert alert{};
    alert.capture_ts_us = record.timestamp_us;
    alert.alert_ts_us = alert_timestamp_us;
    alert.interface_name = record.interface_name;
    alert.rule = rule;
    alert.severity = severity;
    alert.can_id = record.can_id;
    alert.id_type = record.id_type;
    alert.dlc = record.dlc;
    std::copy_n(record.data.begin(), record.dlc, alert.data.begin());
    alert.detail = std::move(detail);
    return alert;
}

std::vector<Alert> identity_alerts(const IdProfile* entry, const CanFrameRecord& record,
                                   uint64_t alert_timestamp_us) {
    const bool unknown = entry == nullptr;
    if (!unknown && entry->allowed_dlc.count(record.dlc) != 0) {
        return {};
    }

    std::ostringstream detail;
    if (unknown) {
        detail << "CAN ID 0x" << std::uppercase << std::hex << record.can_id
               << " (" << (record.id_type == IdType::Standard11 ? "standard" : "extended")
               << ") is absent from baseline";
    } else {
        detail << "observed_dlc=" << static_cast<unsigned>(record.dlc) << " allowed_dlc=";
        bool first = true;
        for (const auto dlc : entry->allowed_dlc) {
            if (!first) {
                detail << ',';
            }
            first = false;
            detail << static_cast<unsigned>(dlc);
        }
    }
    return {make_alert(record, alert_timestamp_us,
                       unknown ? AlertRule::UnknownId : AlertRule::DlcMismatch,
                       Severity::High, detail.str())};
}

std::string fixed_byte_detail(const IdProfile& profile, const CanFrameRecord& record) {
    std::ostringstream detail;
    detail << std::uppercase << std::setfill('0');
    bool first = true;
    for (std::size_t index = 0; index < record.dlc; ++index) {
        const auto effective_mask = static_cast<uint8_t>(profile.fixed_mask[index] & ~profile.ignore_mask[index]);
        if ((record.data[index] & effective_mask) == (profile.fixed_value[index] & effective_mask)) {
            continue;
        }
        detail << (first ? "fixed_byte_mismatches=[" : "; ");
        first = false;
        detail << "index=" << std::dec << index
               << " observed=0x" << std::hex << std::setw(2) << static_cast<unsigned>(record.data[index])
               << " expected=0x" << std::setw(2) << static_cast<unsigned>(profile.fixed_value[index])
               << " effective_mask=0x" << std::setw(2) << static_cast<unsigned>(effective_mask);
    }
    if (!first) {
        detail << ']';
    }
    return detail.str();
}

}  // namespace

std::vector<Alert> detect_identity_rules(
    const DetectionBaseline& baseline,
    const CanFrameRecord& record,
    uint64_t alert_timestamp_us
) {
    validate_record(record);
    return identity_alerts(find_profile(baseline, record), record, alert_timestamp_us);
}

Detector::Detector(DetectionBaseline baseline) : baseline_(std::move(baseline)) {
    if (baseline_.window_ms != 100) {
        throw std::invalid_argument("detector requires window_ms=100");
    }
    for (const auto& entry : baseline_.entries) {
        if (entry.rate_limit_100ms <= 0) {
            throw std::invalid_argument("detector requires a positive rate_limit_100ms");
        }
        if (entry.max_identical_payload_run <= 0) {
            throw std::invalid_argument("detector requires a positive max_identical_payload_run");
        }
    }
}

std::vector<Alert> Detector::process(const CanFrameRecord& record, uint64_t alert_timestamp_us) {
    validate_record(record);
    const auto* entry = find_profile(baseline_, record);
    if (entry == nullptr) {
        return identity_alerts(nullptr, record, alert_timestamp_us);
    }

    const StateKey key{record.interface_name, record.id_type, record.can_id};
    const auto previous = histories_.find(key);
    if (previous != histories_.end() && previous->second.last_timestamp_us &&
        record.timestamp_us < *previous->second.last_timestamp_us) {
        throw std::invalid_argument("capture timestamp decreased for the same interface and typed CAN ID");
    }

    auto alerts = identity_alerts(entry, record, alert_timestamp_us);
    auto& history = histories_[key];
    const auto now = record.timestamp_us;
    if (entry->periodic && history.last_timestamp_us) {
        const auto delta = now - *history.last_timestamp_us;
        if (delta < entry->period_min_us || delta > entry->period_max_us) {
            const auto detail = "delta_us=" + std::to_string(delta) +
                                " allowed_min_us=" + std::to_string(entry->period_min_us) +
                                " allowed_max_us=" + std::to_string(entry->period_max_us);
            alerts.push_back(make_alert(record, alert_timestamp_us, AlertRule::PeriodViolation,
                                         Severity::Medium, detail));
        }
    }

    // History is nondecreasing, so subtraction cannot underflow. The window is
    // (now - 100000us, now], matching profile generation's exact-boundary rule.
    while (!history.recent_timestamps_us.empty() && now - history.recent_timestamps_us.front() >= 100000ULL) {
        history.recent_timestamps_us.pop_front();
    }
    history.recent_timestamps_us.push_back(now);
    history.last_timestamp_us = now;
    const auto count = history.recent_timestamps_us.size();
    if (count > static_cast<std::size_t>(entry->rate_limit_100ms)) {
        const auto detail = "count_100ms=" + std::to_string(count) +
                            " threshold=" + std::to_string(entry->rate_limit_100ms);
        alerts.push_back(make_alert(record, alert_timestamp_us, AlertRule::RateSpike,
                                     Severity::High, detail));
    }

    const auto fixed_detail = fixed_byte_detail(*entry, record);
    if (!fixed_detail.empty()) {
        alerts.push_back(make_alert(record, alert_timestamp_us, AlertRule::FixedByteViolation,
                                     Severity::Medium, fixed_detail));
    }

    const bool identical = history.identical_payload_run != 0 && history.last_dlc == record.dlc &&
        std::equal(record.data.begin(), record.data.begin() + record.dlc, history.last_payload.begin());
    if (!identical) {
        history.identical_payload_run = 1;
    } else if (history.identical_payload_run != std::numeric_limits<uint64_t>::max()) {
        // Saturate instead of wrapping around.
        ++history.identical_payload_run;
    }
    history.last_dlc = record.dlc;
    history.last_payload.fill(0);
    std::copy_n(record.data.begin(), record.dlc, history.last_payload.begin());
    if (history.identical_payload_run > static_cast<uint64_t>(entry->max_identical_payload_run)) {
        const auto detail = "identical_payload_run=" + std::to_string(history.identical_payload_run) +
                            " threshold=" + std::to_string(entry->max_identical_payload_run);
        alerts.push_back(make_alert(record, alert_timestamp_us, AlertRule::ReplayBurst,
                                     Severity::High, detail));
    }
    return alerts;
}

}  // namespace cansec
