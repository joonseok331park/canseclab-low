#pragma once

#include "cansec/types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace cansec {

struct ReportMetadata {
    std::string started_utc;
    std::string finished_utc;
    std::string termination_reason;
    std::string mode;
    std::string git_commit;
    std::string source_sha256;
    std::string build_type;
    std::string compiler;
    std::string os;
    std::string kernel;
    std::string interface_name;
    std::string rules_path;
    std::string rules_sha256;
    std::string input_path;
    std::string input_sha256;
    std::string alerts_path;
    std::string alerts_sha256;
    std::string command_line;
    uint64_t elapsed_us = 0;
    uint64_t max_frames = 0;
    uint64_t max_seconds = 0;
};

class DetectionReport {
public:
    // Called once per checked frame, with all alerts raised for it (maybe none).
    void observe(const CanFrameRecord& frame, const std::vector<Alert>& alerts);
    uint64_t processed_frames() const { return processed_frames_; }
    uint64_t alert_count() const { return alert_count_; }

private:
    uint64_t processed_frames_ = 0;
    uint64_t alert_count_ = 0;
    uint64_t first_frame_timestamp_ = 0;
    uint64_t last_frame_timestamp_ = 0;
    std::set<std::pair<IdType, uint32_t>> unique_ids_;
    std::array<std::array<uint64_t, 3>, 6> rule_severity_counts_{};
    // First alerts in the order they were seen.
    std::array<Alert, 10> first_alerts_{};
    std::size_t first_alert_count_ = 0;

    friend std::string format_detection_report(const ReportMetadata&,
                                               const DetectionReport&);
};

std::string format_detection_report(const ReportMetadata& metadata,
                                    const DetectionReport& report);

}  // namespace cansec
