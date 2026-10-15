#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "cansec/baseline.hpp"
#include "cansec/types.hpp"

namespace cansec {

// Stateless UNKNOWN_ID / DLC_MISMATCH check. An unknown ID only raises
// UNKNOWN_ID. The baseline must come from load_baseline_ini.
std::vector<Alert> detect_identity_rules(
    const DetectionBaseline& baseline,
    const CanFrameRecord& record,
    uint64_t alert_timestamp_us
);

class Detector {
public:
    explicit Detector(DetectionBaseline baseline);

    // Runs identity, period, rate, fixed-byte and replay rules in that order.
    // History is kept per (interface, ID type, ID). A timestamp older than the
    // last one for the same key throws std::invalid_argument.
    std::vector<Alert> process(const CanFrameRecord& record, uint64_t alert_timestamp_us);

private:
    using StateKey = std::tuple<std::string, IdType, uint32_t>;
    struct History {
        std::optional<uint64_t> last_timestamp_us;
        std::deque<uint64_t> recent_timestamps_us;
        uint8_t last_dlc = 0;
        std::array<uint8_t, 8> last_payload{};
        uint64_t identical_payload_run = 0;
    };

    DetectionBaseline baseline_;
    std::map<StateKey, History> histories_;
};

}  // namespace cansec
