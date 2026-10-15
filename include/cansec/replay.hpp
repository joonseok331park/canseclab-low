#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "cansec/types.hpp"

namespace cansec {

struct ReplaySchedule {
    // Offsets for a single loop.
    std::vector<uint64_t> offsets_us;
    uint64_t loop_count = 1;
    uint64_t loop_duration_us = 0;
    // Offset of the last frame (initial delay not included).
    uint64_t total_duration_us = 0;
    uint64_t total_frames = 0;
};

// Builds send offsets from log timestamps: (t - t0) / speed, rounded down.
// The whole log is checked first (non-empty, timestamps never decreasing).
// Loops follow each other with no gap. Throws std::overflow_error if the
// totals do not fit in uint64_t.
ReplaySchedule make_replay_schedule(const std::vector<CanFrameRecord>& records,
                                    long double speed = 1.0L,
                                    uint64_t loop_count = 1);

struct ReplayPlan {
    std::vector<CanFrameRecord> records;
    ReplaySchedule schedule;
    // Waited once before the first frame only.
    uint64_t initial_delay_us = 0;
};

// Sends one frame `count` times, interval_us apart.
ReplayPlan make_flood_plan(const CanFrameRecord& record, uint64_t interval_us,
                           uint64_t count);

// XORs the payload with flip_mask (one 00/FF byte per data byte) and sends
// the resulting frame `count` times, period_us apart.
ReplayPlan make_fuzz_plan(const CanFrameRecord& base, const std::vector<uint8_t>& flip_mask,
                          uint64_t period_us, uint64_t count);

// Replays file lines [start_line, end_line] (1-based, blank and comment lines
// included in the count). The whole file is parsed and checked first.
ReplayPlan make_segment_replay_plan(const std::string& path, uint64_t start_line,
                                    uint64_t end_line, uint64_t delay_ms,
                                    uint64_t repeat);

}  // namespace cansec
