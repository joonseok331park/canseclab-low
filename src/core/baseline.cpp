#include "cansec/baseline.hpp"

#include <array>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

namespace cansec {
namespace {

struct Location {
    const std::string& path;
    std::size_t line = 0;
    std::string section;
    std::string key;
};

[[noreturn]] void fail(const Location& location, const std::string& message) {
    std::string context = location.path;
    if (location.line != 0) {
        context += ":" + std::to_string(location.line);
    }
    if (!location.section.empty()) {
        context += " " + location.section;
    }
    if (!location.key.empty()) {
        context += " key '" + location.key + "'";
    }
    throw std::runtime_error(context + ": " + message);
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}

uint64_t unsigned_integer(const std::string& value, uint64_t maximum, const Location& location) {
    if (value.empty()) {
        fail(location, "expected an unsigned decimal integer");
    }
    uint64_t result = 0;
    for (const char ch : value) {
        if (ch < '0' || ch > '9') {
            fail(location, "expected an unsigned decimal integer without trailing text");
        }
        const auto digit = static_cast<uint64_t>(ch - '0');
        if (digit > maximum || result > (maximum - digit) / 10) {
            fail(location, "integer value is out of range");
        }
        result = result * 10 + digit;
    }
    return result;
}

unsigned hex_digit(char ch, const Location& location) {
    if (ch >= '0' && ch <= '9') {
        return static_cast<unsigned>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<unsigned>(ch - 'a' + 10);
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<unsigned>(ch - 'A' + 10);
    }
    fail(location, "invalid hexadecimal digit");
}

uint32_t section_id(const std::string& section, const Location& location) {
    if (section.size() < 8 || section.compare(0, 6, "[id:0x") != 0 || section.back() != ']') {
        fail(location, "expected [global] or [id:0xHEX] section");
    }
    uint32_t result = 0;
    for (std::size_t i = 6; i + 1 < section.size(); ++i) {
        const auto digit = hex_digit(section[i], location);
        if (result > (0x1FFFFFFFU - digit) / 16) {
            fail(location, "CAN ID exceeds 29-bit range");
        }
        result = result * 16 + digit;
    }
    return result;
}

std::array<uint8_t, 8> byte_array(const std::string& value, const Location& location) {
    if (value.size() != 16) {
        fail(location, "expected exactly 16 hexadecimal digits");
    }
    std::array<uint8_t, 8> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>(hex_digit(value[2 * i], location) * 16 +
                                        hex_digit(value[2 * i + 1], location));
    }
    return bytes;
}

std::set<uint8_t> allowed_dlc(const std::string& value, const Location& location) {
    std::set<uint8_t> result;
    std::size_t start = 0;
    while (true) {
        const auto comma = value.find(',', start);
        const auto token = trim(value.substr(start, comma == std::string::npos ? comma : comma - start));
        const auto dlc = static_cast<uint8_t>(unsigned_integer(token, 8, location));
        if (!result.insert(dlc).second) {
            fail(location, "duplicate DLC value");
        }
        if (comma == std::string::npos) {
            return result;
        }
        start = comma + 1;
    }
}

struct Section {
    std::string name;
    std::size_t first_line = 0;
    std::map<std::string, std::size_t> keys;
    IdProfile profile;
};

void finish_section(const Section& section, DetectionBaseline& baseline, const std::string& path) {
    Location location{path, section.first_line, section.name, {}};
    if (section.name == "[global]") {
        if (section.keys.count("window_ms") == 0) {
            location.key = "window_ms";
            fail(location, "required key is missing");
        }
        return;
    }

    static const std::array<const char*, 10> required{{
        "id_type", "allowed_dlc", "periodic", "period_min_us", "period_max_us",
        "rate_limit_100ms", "fixed_mask", "fixed_value", "ignore_mask", "max_identical_payload_run"
    }};
    for (const auto key : required) {
        if (section.keys.count(key) == 0) {
            location.key = key;
            fail(location, "required key is missing");
        }
    }
    const auto& profile = section.profile;
    if (profile.id_type == IdType::Standard11 && profile.can_id > 0x7FFU) {
        location.line = section.keys.at("id_type");
        location.key = "id_type";
        fail(location, "standard CAN ID exceeds 11-bit range");
    }
    location.line = section.keys.at("period_min_us");
    location.key = "period_min_us/period_max_us";
    if (profile.period_min_us > profile.period_max_us) {
        fail(location, "period minimum exceeds maximum");
    }
    if (!profile.periodic && (profile.period_min_us != 0 || profile.period_max_us != 0)) {
        fail(location, "nonperiodic ID requires a zero period range");
    }
    baseline.entries.push_back(profile);
}

void read_policy_value(IdProfile& profile, const std::string& key,
                       const std::string& value, const Location& location) {
    static const std::set<std::string> metadata{
        "frame_count", "first_timestamp_us", "last_timestamp_us", "median_delta_us",
        "p05_delta_us", "p95_delta_us", "max_count_per_100ms"
    };
    if (key == "id_type") {
        if (value != "standard" && value != "extended") {
            fail(location, "id_type must be standard or extended");
        }
        profile.id_type = value == "extended" ? IdType::Extended29 : IdType::Standard11;
    } else if (key == "allowed_dlc") {
        profile.allowed_dlc = allowed_dlc(value, location);
    } else if (key == "periodic") {
        if (value != "0" && value != "1") {
            fail(location, "periodic must be 0 or 1");
        }
        profile.periodic = value == "1";
    } else if (key == "period_min_us" || key == "period_max_us") {
        const auto parsed = unsigned_integer(value, std::numeric_limits<uint64_t>::max(), location);
        if (key == "period_min_us") {
            profile.period_min_us = parsed;
        } else {
            profile.period_max_us = parsed;
        }
    } else if (key == "rate_limit_100ms" || key == "max_identical_payload_run") {
        const auto parsed = static_cast<int>(unsigned_integer(value, std::numeric_limits<int>::max(), location));
        if (parsed == 0) {
            fail(location, "value must be positive");
        }
        if (key == "rate_limit_100ms") {
            profile.rate_limit_100ms = parsed;
        } else {
            profile.max_identical_payload_run = parsed;
        }
    } else if (key == "fixed_mask") {
        profile.fixed_mask = byte_array(value, location);
    } else if (key == "fixed_value") {
        profile.fixed_value = byte_array(value, location);
    } else if (key == "ignore_mask") {
        profile.ignore_mask = byte_array(value, location);
    } else if (metadata.count(key) == 0) {
        fail(location, "unknown ID policy or metadata key");
    }
}

}  // namespace

DetectionBaseline load_baseline_ini(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        fail({path, 0, {}, {}}, "failed to open baseline file");
    }
    DetectionBaseline baseline;
    bool global_seen = false;
    std::set<uint32_t> seen_ids;
    std::optional<Section> current;
    static const std::set<std::string> global_metadata{
        "created_utc", "benign_source", "benign_source_sha256", "override_source",
        "override_source_sha256", "period_margin_ratio", "rate_margin_ratio"
    };
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        if (line_number == 1 && line.compare(0, 3, "\xEF\xBB\xBF") == 0) {
            line.erase(0, 3);
        }
        Location location{path, line_number, current ? current->name : "", {}};
        if (line.find('\0') != std::string::npos) {
            fail(location, "NUL byte in text baseline");
        }
        line = trim(line);
        if (line.empty() || line.front() == '#' || line.front() == ';') {
            continue;
        }
        if (line.front() == '[') {
            if (current) {
                finish_section(*current, baseline, path);
            }
            location.section = line;
            Section next{line, line_number, {}, {}};
            if (line == "[global]") {
                if (global_seen) {
                    fail(location, "duplicate global section");
                }
                global_seen = true;
            } else {
                next.profile.can_id = section_id(line, location);
                if (!seen_ids.insert(next.profile.can_id).second) {
                    fail(location, "duplicate numeric CAN ID section");
                }
            }
            current = std::move(next);
            continue;
        }
        const auto equals = line.find('=');
        if (!current || equals == std::string::npos) {
            fail(location, "expected key=value inside a section");
        }
        const auto key = trim(line.substr(0, equals));
        const auto value = trim(line.substr(equals + 1));
        location.key = key;
        if (!current->keys.emplace(key, line_number).second) {
            fail(location, "duplicate key");
        }
        if (current->name == "[global]") {
            if (key == "window_ms") {
                const auto window = unsigned_integer(value, std::numeric_limits<int>::max(), location);
                if (window != 100) {
                    fail(location, "v1 requires window_ms=100");
                }
                baseline.window_ms = static_cast<int>(window);
            } else if (global_metadata.count(key) == 0) {
                fail(location, "unknown global key");
            }
        } else {
            read_policy_value(current->profile, key, value, location);
        }
    }
    if (input.bad() || !input.eof()) {
        fail({path, line_number + 1, current ? current->name : "", {}}, "failed to read baseline file");
    }
    if (current) {
        finish_section(*current, baseline, path);
    }
    if (!global_seen) {
        fail({path, line_number + 1, {}, {}}, "required [global] section is missing");
    }
    if (baseline.entries.empty()) {
        fail({path, line_number + 1, {}, {}}, "baseline must contain at least one ID section");
    }
    return baseline;
}

}  // namespace cansec
