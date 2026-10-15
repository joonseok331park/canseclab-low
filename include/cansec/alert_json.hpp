#pragma once

#include <string>

#include "cansec/types.hpp"

namespace cansec {

// Serializes one alert as a single JSON line (no trailing newline).
// Throws std::invalid_argument on an invalid ID/DLC or malformed UTF-8.
std::string format_alert_json(const Alert& alert);

}  // namespace cansec
