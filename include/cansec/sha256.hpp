#pragma once

#include <string>

namespace cansec {

// Throws std::runtime_error if the file cannot be read.
std::string sha256_file(const std::string& path);

}  // namespace cansec
