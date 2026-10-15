#pragma once

#include <array>
#include <cstdint>
#include <set>
#include <string>

namespace cansec {

enum class IdType {
    Standard11,
    Extended29
};

struct CanFrameRecord {
    uint64_t timestamp_us = 0;
    std::string interface_name;
    uint32_t can_id = 0;
    IdType id_type = IdType::Standard11;
    uint8_t dlc = 0;
    std::array<uint8_t, 8> data{};
};

enum class Severity {
    Low,
    Medium,
    High
};

enum class AlertRule {
    UnknownId,
    DlcMismatch,
    PeriodViolation,
    RateSpike,
    FixedByteViolation,
    ReplayBurst
};

struct Alert {
    uint64_t capture_ts_us = 0;
    uint64_t alert_ts_us = 0;
    std::string interface_name;
    AlertRule rule = AlertRule::UnknownId;
    Severity severity = Severity::Low;
    uint32_t can_id = 0;
    IdType id_type = IdType::Standard11;
    uint8_t dlc = 0;
    std::array<uint8_t, 8> data{};
    std::string detail;
};

struct IdProfile {
    uint32_t can_id = 0;
    IdType id_type = IdType::Standard11;
    std::set<uint8_t> allowed_dlc;
    bool periodic = false;
    uint64_t period_min_us = 0;
    uint64_t period_max_us = 0;
    int rate_limit_100ms = 0;
    std::array<uint8_t, 8> fixed_mask{};
    std::array<uint8_t, 8> fixed_value{};
    std::array<uint8_t, 8> ignore_mask{};
    int max_identical_payload_run = 0;
};


}  // namespace cansec
