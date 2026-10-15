#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "cansec/types.hpp"

namespace cansec {

struct BaselineBuildOptions {
    int window_ms = 100;
    double period_margin_ratio = 0.2;
    double rate_margin_ratio = 0.2;
    std::size_t min_periodic_frames = 30;
    uint64_t periodic_median_max_us = 200000;
    double periodic_jitter_ratio_max = 2.5;
};

struct IdProfileStats {
    uint32_t can_id = 0;
    IdType id_type = IdType::Standard11;

    std::size_t frame_count = 0;
    uint64_t first_timestamp_us = 0;
    uint64_t last_timestamp_us = 0;

    uint64_t median_delta_us = 0;
    uint64_t p05_delta_us = 0;
    uint64_t p95_delta_us = 0;

    int max_count_per_100ms = 0;

    IdProfile profile;
};

struct BaselineProfile {
    std::string created_utc;
    std::string benign_source;
    std::string benign_source_sha256;
    std::string override_source;
    std::string override_source_sha256;

    int window_ms = 100;
    double period_margin_ratio = 0.2;
    double rate_margin_ratio = 0.2;

    std::vector<IdProfileStats> entries;
};

BaselineProfile build_baseline_profile(
    const std::vector<CanFrameRecord>& records,
    const std::string& benign_source,
    const BaselineBuildOptions& options = BaselineBuildOptions{}
);

// Applies per-ID policy overrides. On any error the baseline is left unchanged.
// Observed statistics are not overridable.
void apply_baseline_overrides(
    BaselineProfile& baseline,
    const std::string& override_path
);

void write_baseline_ini(
    const BaselineProfile& baseline,
    const std::string& output_path
);

void write_profile_summary(
    const BaselineProfile& baseline,
    const std::string& output_path
);

}  // namespace cansec
