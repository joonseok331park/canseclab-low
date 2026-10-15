#include "cansec/logio.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cansec {

namespace {

std::string trim_copy(const std::string& value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch);
    });

    if (first == value.end()) {
        return "";
    }

    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch);
    }).base();

    return std::string(first, last);
}

bool is_decimal_string(const std::string& value) {
    if (value.empty()) {
        return false;
    }

    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isdigit(ch);
    });
}

bool is_hex_string(const std::string& value) {
    if (value.empty()) {
        return false;
    }

    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isxdigit(ch);
    });
}

uint64_t parse_decimal_u64_exact(const std::string& value, const std::string& field_name) {
    if (!is_decimal_string(value)) {
        throw std::runtime_error("invalid decimal value for " + field_name + ": " + value);
    }

    std::size_t index = 0;
    const uint64_t parsed = std::stoull(value, &index, 10);

    if (index != value.size()) {
        throw std::runtime_error("invalid trailing character in " + field_name + ": " + value);
    }

    return parsed;
}

uint32_t parse_hex_u32_exact(const std::string& value, const std::string& field_name) {
    if (!is_hex_string(value)) {
        throw std::runtime_error("invalid hex value for " + field_name + ": " + value);
    }

    std::size_t index = 0;
    const unsigned long parsed = std::stoul(value, &index, 16);

    if (index != value.size()) {
        throw std::runtime_error("invalid trailing character in " + field_name + ": " + value);
    }

    if (parsed > 0x1FFFFFFFUL) {
        throw std::runtime_error("CAN ID exceeds 29-bit range: " + value);
    }

    return static_cast<uint32_t>(parsed);
}

int parse_hex_digit(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    throw std::runtime_error("invalid hex digit");
}

uint8_t parse_hex_byte(char high, char low) {
    const int hi = parse_hex_digit(high);
    const int lo = parse_hex_digit(low);
    return static_cast<uint8_t>((hi << 4) | lo);
}

uint64_t parse_timestamp_us(const std::string& token) {
    if (token.size() < 4 || token.front() != '(' || token.back() != ')') {
        throw std::runtime_error("invalid timestamp token: " + token);
    }

    const std::string inner = token.substr(1, token.size() - 2);
    const std::size_t dot_pos = inner.find('.');

    if (dot_pos == std::string::npos) {
        throw std::runtime_error("timestamp must contain '.' separator: " + token);
    }

    const std::string sec_part = inner.substr(0, dot_pos);
    std::string usec_part = inner.substr(dot_pos + 1);

    if (usec_part.empty() || usec_part.size() > 6) {
        throw std::runtime_error("timestamp microseconds must have 1 to 6 digits: " + token);
    }

    while (usec_part.size() < 6) {
        usec_part.push_back('0');
    }

    const uint64_t sec = parse_decimal_u64_exact(sec_part, "timestamp seconds");
    const uint64_t usec = parse_decimal_u64_exact(usec_part, "timestamp microseconds");

    if (sec > (std::numeric_limits<uint64_t>::max() - usec) / 1000000ULL) {
        throw std::runtime_error("timestamp exceeds 64-bit microsecond range: " + token);
    }
    return sec * 1000000ULL + usec;
}

}  // namespace

std::string format_can_record(const CanFrameRecord& record) {
    std::ostringstream oss;

    const uint64_t sec = record.timestamp_us / 1000000ULL;
    const uint64_t usec = record.timestamp_us % 1000000ULL;

    oss << "(" << sec << "."
        << std::setw(6) << std::setfill('0') << usec
        << ") ";

    oss << record.interface_name << " ";

    oss << std::uppercase << std::hex << std::setfill('0');

    if (record.id_type == IdType::Extended29) {
        oss << std::setw(8) << record.can_id;
    } else {
        oss << std::setw(3) << record.can_id;
    }

    oss << "#";

    for (uint8_t i = 0; i < record.dlc && i < 8; ++i) {
        oss << std::setw(2) << static_cast<int>(record.data[i]);
    }

    return oss.str();
}

void write_can_record(std::ostream& os, const CanFrameRecord& record) {
    os << format_can_record(record) << '\n';
}

bool is_ignorable_log_line(const std::string& line) {
    const std::string trimmed = trim_copy(line);
    return trimmed.empty() || trimmed.front() == '#';
}

std::optional<CanFrameRecord> parse_can_record_line(const std::string& line) {
    if (is_ignorable_log_line(line)) {
        return std::nullopt;
    }

    std::istringstream iss(line);

    std::string timestamp_token;
    std::string interface_token;
    std::string frame_token;

    if (!(iss >> timestamp_token >> interface_token >> frame_token)) {
        throw std::runtime_error("invalid log line: expected '(sec.usec) interface id#payload'");
    }

    std::string extra_token;
    if (iss >> extra_token) {
        throw std::runtime_error("invalid log line: unexpected extra token '" + extra_token + "'");
    }

    const uint64_t timestamp_us = parse_timestamp_us(timestamp_token);

    const std::size_t hash_pos = frame_token.find('#');
    if (hash_pos == std::string::npos) {
        throw std::runtime_error("CAN frame token must contain '#': " + frame_token);
    }

    const std::string can_id_part = frame_token.substr(0, hash_pos);
    const std::string payload_part = frame_token.substr(hash_pos + 1);

    if (can_id_part.empty()) {
        throw std::runtime_error("missing CAN ID");
    }
    if (can_id_part.size() > 8) {
        throw std::runtime_error("CAN ID must have at most 8 hex digits: " + can_id_part);
    }

    if (payload_part.size() % 2 != 0) {
        throw std::runtime_error("payload hex length must be even: " + payload_part);
    }

    if (payload_part.size() > 16) {
        throw std::runtime_error("Classical CAN payload must be at most 8 bytes: " + payload_part);
    }

    if (!payload_part.empty() && !is_hex_string(payload_part)) {
        throw std::runtime_error("invalid payload hex: " + payload_part);
    }

    CanFrameRecord record;
    record.timestamp_us = timestamp_us;
    record.interface_name = interface_token;
    record.can_id = parse_hex_u32_exact(can_id_part, "CAN ID");
    // Canonical extended IDs use eight digits, including IDs below 0x800.
    record.id_type = can_id_part.size() == 8 || record.can_id > 0x7FF
        ? IdType::Extended29 : IdType::Standard11;
    record.dlc = static_cast<uint8_t>(payload_part.size() / 2);

    for (uint8_t i = 0; i < record.dlc; ++i) {
        record.data[i] = parse_hex_byte(payload_part[i * 2], payload_part[i * 2 + 1]);
    }

    return record;
}

std::vector<CanFrameRecord> read_can_log_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open CAN log file: " + path);
    }

    std::vector<CanFrameRecord> records;

    std::string line;
    int line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;

        try {
            auto record = parse_can_record_line(line);
            if (record.has_value()) {
                records.push_back(record.value());
            }
        } catch (const std::exception& e) {
            throw std::runtime_error(path + ":" + std::to_string(line_number) + ": " + e.what());
        }
    }

    if (!input.eof()) {
        throw std::runtime_error("failed to read CAN log file: " + path);
    }

    return records;
}

}  // namespace cansec
