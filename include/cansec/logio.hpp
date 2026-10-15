#pragma once

#include <iosfwd>
#include <optional>
#include <string>
#include <vector>

#include "cansec/types.hpp"

namespace cansec {

std::string format_can_record(const CanFrameRecord& record);

void write_can_record(std::ostream& os, const CanFrameRecord& record);

bool is_ignorable_log_line(const std::string& line);

std::optional<CanFrameRecord> parse_can_record_line(const std::string& line);

std::vector<CanFrameRecord> read_can_log_file(const std::string& path);

}  // namespace cansec
