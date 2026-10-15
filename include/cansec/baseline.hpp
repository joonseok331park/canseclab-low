#pragma once

#include <string>
#include <vector>

#include "cansec/types.hpp"

namespace cansec {

struct DetectionBaseline {
    int window_ms = 100;
    std::vector<IdProfile> entries;
};

// Throws std::runtime_error with the file/line context if anything is invalid.
DetectionBaseline load_baseline_ini(const std::string& path);

}  // namespace cansec
