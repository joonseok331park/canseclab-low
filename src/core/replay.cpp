#include "cansec/replay.hpp"
#include "cansec/logio.hpp"

#include <cmath>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>

namespace cansec {
namespace {

void validate_frame(const CanFrameRecord& record, std::size_t index) {
    const std::string context = "replay frame " + std::to_string(index + 1) + ": ";
    switch (record.id_type) {
        case IdType::Standard11:
            if (record.can_id > 0x7FFU) {
                throw std::invalid_argument(context + "standard CAN ID exceeds 11 bits");
            }
            break;
        case IdType::Extended29:
            if (record.can_id > 0x1FFFFFFFU) {
                throw std::invalid_argument(context + "extended CAN ID exceeds 29 bits");
            }
            break;
        default:
            throw std::invalid_argument(context + "invalid ID type");
    }
    if (record.dlc > 8) {
        throw std::invalid_argument(context + "DLC must be between 0 and 8");
    }
}

uint64_t scaled_offset(uint64_t relative_us, long double speed) {
    // Preserve all 64 timestamp bits at the default speed, even on targets
    // whose long double has fewer than 64 mantissa bits.
    if (speed == 1.0L || relative_us == 0) return relative_us;
    const long double scaled = std::floor(static_cast<long double>(relative_us) / speed);
    // 2^64 is exactly representable; comparing against a rounded UINT64_MAX
    // could otherwise permit an out-of-range floating-to-integer conversion.
    if (!std::isfinite(scaled) || scaled >= std::ldexp(1.0L, 64)) {
        throw std::overflow_error("replay timestamp offset exceeds uint64 microsecond range");
    }
    return static_cast<uint64_t>(scaled);
}

ReplayPlan make_interval_plan(const CanFrameRecord& record, uint64_t interval_us,
                              uint64_t count, const std::string& mode,
                              const std::string& interval_field) {
    validate_frame(record, 0);
    if (interval_us == 0) {
        throw std::invalid_argument(mode + " " + interval_field + " must be positive");
    }
    if (count == 0) {
        throw std::invalid_argument(mode + " count must be positive");
    }
    if (count - 1 > std::numeric_limits<uint64_t>::max() / interval_us) {
        throw std::overflow_error(mode + " total duration exceeds uint64 microsecond range");
    }

    ReplayPlan plan;
    plan.records.push_back(record);
    plan.schedule.offsets_us = {0};
    plan.schedule.loop_count = count;
    plan.schedule.loop_duration_us = interval_us;
    plan.schedule.total_duration_us = (count - 1) * interval_us;
    plan.schedule.total_frames = count;
    return plan;
}

}  // namespace

ReplaySchedule make_replay_schedule(const std::vector<CanFrameRecord>& records,
                                    long double speed, uint64_t loop_count) {
    if (!std::isfinite(speed) || speed <= 0) {
        throw std::invalid_argument("replay speed must be finite and positive");
    }
    if (loop_count == 0) {
        throw std::invalid_argument("replay loop count must be positive");
    }
    if (records.empty()) {
        throw std::invalid_argument("no CAN frames in replay log");
    }

    const auto maximum = std::numeric_limits<uint64_t>::max();
    if (records.size() > maximum / loop_count) {
        throw std::overflow_error("replay total frame count exceeds uint64 range");
    }

    ReplaySchedule schedule;
    schedule.loop_count = loop_count;
    schedule.total_frames = static_cast<uint64_t>(records.size()) * loop_count;
    schedule.offsets_us.reserve(records.size());
    const uint64_t first_us = records.front().timestamp_us;
    uint64_t previous_us = first_us;
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto& record = records[i];
        validate_frame(record, i);
        if (record.timestamp_us < previous_us) {
            throw std::invalid_argument("replay frame " + std::to_string(i + 1) +
                                        ": timestamp moves backwards");
        }
        // Subtract in the original integer domain before scaling: a large
        // absolute epoch must not erase small differences between frames.
        schedule.offsets_us.push_back(scaled_offset(record.timestamp_us - first_us, speed));
        previous_us = record.timestamp_us;
    }
    schedule.loop_duration_us = schedule.offsets_us.back();
    if (schedule.loop_duration_us > maximum / loop_count) {
        throw std::overflow_error("replay total duration exceeds uint64 microsecond range");
    }
    schedule.total_duration_us = schedule.loop_duration_us * loop_count;
    return schedule;
}

ReplayPlan make_flood_plan(const CanFrameRecord& record, uint64_t interval_us,
                           uint64_t count) {
    return make_interval_plan(record, interval_us, count, "flood", "interval_us");
}

ReplayPlan make_fuzz_plan(const CanFrameRecord& base, const std::vector<uint8_t>& flip_mask,
                          uint64_t period_us, uint64_t count) {
    auto plan = make_interval_plan(base, period_us, count, "fuzz", "period_us");
    if (flip_mask.size() != base.dlc) {
        throw std::invalid_argument("fuzz flip_mask length must equal DLC");
    }
    for (std::size_t i = 0; i < flip_mask.size(); ++i) {
        if (flip_mask[i] != 0x00 && flip_mask[i] != 0xFF) {
            throw std::invalid_argument("fuzz flip_mask byte " + std::to_string(i) + " must be 00 or FF");
        }
        plan.records.front().data[i] ^= flip_mask[i];
    }
    return plan;
}

ReplayPlan make_segment_replay_plan(const std::string& path, uint64_t start_line,
                                    uint64_t end_line, uint64_t delay_ms,
                                    uint64_t repeat) {
    if (start_line == 0 || end_line < start_line) {
        throw std::invalid_argument(path + ": start_line must be at least 1 and end_line must be at least start_line");
    }
    if (repeat == 0) {
        throw std::invalid_argument(path + ": repeat must be positive");
    }
    const auto maximum = std::numeric_limits<uint64_t>::max();
    if (delay_ms > maximum / 1000ULL) {
        throw std::overflow_error(path + ": delay_ms exceeds uint64 microsecond range");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open CAN log file: " + path);
    }

    ReplayPlan plan;
    plan.initial_delay_us = delay_ms * 1000ULL;
    uint64_t line_number = 0;
    uint64_t previous_us = 0;
    bool have_previous = false;
    std::string line;
    while (std::getline(input, line)) {
        if (line_number == maximum) {
            throw std::overflow_error(path + ": physical line count exceeds uint64 range");
        }
        ++line_number;
        try {
            const auto record = parse_can_record_line(line);
            if (!record) continue;
            if (have_previous && record->timestamp_us < previous_us) {
                throw std::invalid_argument("timestamp moves backwards");
            }
            previous_us = record->timestamp_us;
            have_previous = true;
            if (line_number >= start_line && line_number <= end_line) {
                plan.records.push_back(*record);
            }
        } catch (const std::exception& error) {
            throw std::runtime_error(path + ":" + std::to_string(line_number) + ": " + error.what());
        }
    }
    if (input.bad() || !input.eof()) {
        throw std::runtime_error("failed to read CAN log file: " + path);
    }
    if (end_line > line_number) {
        throw std::invalid_argument(path + ": end_line exceeds file line count " + std::to_string(line_number));
    }
    if (plan.records.empty()) {
        throw std::invalid_argument(path + ": no CAN frames in selected line range");
    }
    try {
        plan.schedule = make_replay_schedule(plan.records, 1.0L, repeat);
    } catch (const std::overflow_error& error) {
        throw std::overflow_error(path + ": " + error.what());
    } catch (const std::invalid_argument& error) {
        throw std::invalid_argument(path + ": " + error.what());
    }
    if (plan.schedule.total_duration_us > maximum - plan.initial_delay_us) {
        throw std::overflow_error(path + ": initial delay plus total duration exceeds uint64 microsecond range");
    }
    return plan;
}

}  // namespace cansec
