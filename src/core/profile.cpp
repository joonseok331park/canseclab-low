#include "cansec/profile.hpp"
#include "cansec/sha256.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace cansec {

namespace {

void validate_options(const BaselineBuildOptions& options) {
    if (options.window_ms != 100) {
        throw std::runtime_error("v1 rate fields require window_ms=100");
    }
    if (!std::isfinite(options.period_margin_ratio) || options.period_margin_ratio < 0.0 ||
        options.period_margin_ratio > 1.0) {
        throw std::runtime_error("period margin ratio must be finite and between 0 and 1");
    }
    if (!std::isfinite(options.rate_margin_ratio) || options.rate_margin_ratio < 0.0) {
        throw std::runtime_error("rate margin ratio must be finite and nonnegative");
    }
    if (options.min_periodic_frames < 2 || options.periodic_median_max_us == 0 ||
        !std::isfinite(options.periodic_jitter_ratio_max) ||
        options.periodic_jitter_ratio_max < 1.0) {
        throw std::runtime_error("invalid periodic classification options");
    }
}

void validate_record(const CanFrameRecord& record) {
    if (record.id_type != IdType::Standard11 && record.id_type != IdType::Extended29) {
        throw std::runtime_error("invalid CAN ID type in profile input");
    }
    const uint32_t maximum_id = record.id_type == IdType::Standard11 ? 0x7FFU : 0x1FFFFFFFU;
    if (record.can_id > maximum_id || record.dlc > 8) {
        throw std::runtime_error("CAN ID or DLC out of range in profile input");
    }
}

void validate_metadata_text(const std::string& value) {
    if (value.find_first_of("\r\n\0", 0, 3) != std::string::npos) {
        throw std::runtime_error("profile metadata cannot contain a newline or NUL");
    }
}

void finish_output(std::ofstream& output, const std::string& path) {
    output.flush();
    if (!output) {
        throw std::runtime_error("failed to write profile output file: " + path);
    }
    output.close();
    if (!output) {
        throw std::runtime_error("failed to close profile output file: " + path);
    }
}

std::string format_utc_now() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time_value = std::chrono::system_clock::to_time_t(now);

    std::tm tm_value{};

#if defined(_WIN32)
    gmtime_s(&tm_value, &time_value);
#else
    gmtime_r(&time_value, &tm_value);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_value, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string format_can_id(uint32_t can_id) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << can_id;
    return oss.str();
}

std::string id_type_to_string(IdType id_type) {
    return id_type == IdType::Extended29 ? "extended" : "standard";
}

std::string format_allowed_dlc(const std::set<uint8_t>& allowed_dlc) {
    std::ostringstream oss;

    bool first = true;
    for (const auto dlc : allowed_dlc) {
        if (!first) {
            oss << ",";
        }
        first = false;
        oss << static_cast<int>(dlc);
    }

    return oss.str();
}

std::string format_byte_array_hex(const std::array<uint8_t, 8>& values) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0');

    for (const auto value : values) {
        oss << std::setw(2) << static_cast<int>(value);
    }

    return oss.str();
}

std::string payload_key(const CanFrameRecord& record) {
    std::ostringstream oss;
    oss << static_cast<int>(record.dlc) << ":";

    oss << std::uppercase << std::hex << std::setfill('0');
    for (uint8_t i = 0; i < record.dlc && i < 8; ++i) {
        oss << std::setw(2) << static_cast<int>(record.data[i]);
    }

    return oss.str();
}

uint64_t percentile_floor(const std::vector<uint64_t>& sorted_values, std::size_t percent) {
    if (sorted_values.empty()) {
        return 0;
    }

    // floor(percent * (n - 1) / 100), without floating-point or size_t overflow.
    const auto last = sorted_values.size() - 1;
    const auto index = (last / 100) * percent + ((last % 100) * percent) / 100;
    return sorted_values[index];
}

uint64_t median_value(const std::vector<uint64_t>& values) {
    if (values.empty()) {
        return 0;
    }

    const std::size_t n = values.size();
    const std::size_t mid = n / 2;

    if (n % 2 == 1) {
        return values[mid];
    }

    return values[mid - 1] + (values[mid] - values[mid - 1]) / 2;
}

uint64_t scaled_period(uint64_t value, double multiplier, bool round_up) {
    // Range-check before the cast: converting >= 2^64 to uint64_t is UB.
    const double scaled = static_cast<double>(value) * multiplier;
    const double rounded = round_up ? std::ceil(scaled) : std::floor(scaled);
    if (!std::isfinite(rounded) || rounded < 0.0 || rounded >= std::ldexp(1.0, 64)) {
        throw std::runtime_error("computed period exceeds uint64_t range");
    }
    return static_cast<uint64_t>(rounded);
}

int max_count_in_window_us(const std::vector<CanFrameRecord>& records, uint64_t window_us) {
    if (records.empty()) {
        return 0;
    }

    std::vector<uint64_t> timestamps;
    timestamps.reserve(records.size());

    for (const auto& record : records) {
        timestamps.push_back(record.timestamp_us);
    }

    std::sort(timestamps.begin(), timestamps.end());

    std::size_t left = 0;
    int max_count = 0;

    for (std::size_t right = 0; right < timestamps.size(); ++right) {
        while (left < right && timestamps[right] - timestamps[left] >= window_us) {
            ++left;
        }

        const auto count = static_cast<int>(right - left + 1);
        max_count = std::max(max_count, count);
    }

    return max_count;
}

int compute_max_identical_payload_run(const std::vector<CanFrameRecord>& records) {
    if (records.empty()) {
        return 0;
    }

    int max_run = 1;
    int current_run = 1;

    std::string previous = payload_key(records.front());

    for (std::size_t i = 1; i < records.size(); ++i) {
        const std::string current = payload_key(records[i]);

        if (current == previous) {
            ++current_run;
        } else {
            max_run = std::max(max_run, current_run);
            current_run = 1;
            previous = current;
        }
    }

    max_run = std::max(max_run, current_run);
    return max_run;
}

void compute_fixed_bytes(
    const std::vector<CanFrameRecord>& records,
    std::array<uint8_t, 8>& fixed_mask,
    std::array<uint8_t, 8>& fixed_value
) {
    fixed_mask.fill(0);
    fixed_value.fill(0);

    if (records.empty()) {
        return;
    }

    for (std::size_t byte_index = 0; byte_index < 8; ++byte_index) {
        bool present_in_all_frames = true;
        bool same_value = true;

        uint8_t candidate = 0;
        bool candidate_initialized = false;

        for (const auto& record : records) {
            if (record.dlc <= byte_index) {
                present_in_all_frames = false;
                break;
            }

            const uint8_t value = record.data[byte_index];

            if (!candidate_initialized) {
                candidate = value;
                candidate_initialized = true;
            } else if (value != candidate) {
                same_value = false;
                break;
            }
        }

        if (present_in_all_frames && same_value && candidate_initialized) {
            fixed_mask[byte_index] = 0xFF;
            fixed_value[byte_index] = candidate;
        }
    }
}

IdProfileStats build_id_profile_stats(
    uint32_t can_id,
    std::vector<CanFrameRecord> records,
    const BaselineBuildOptions& options
) {
    if (records.empty()) {
        throw std::runtime_error("cannot build profile for empty record group");
    }

    std::stable_sort(records.begin(), records.end(), [](const CanFrameRecord& lhs, const CanFrameRecord& rhs) {
        return lhs.timestamp_us < rhs.timestamp_us;
    });

    IdProfileStats stats;
    stats.can_id = can_id;
    stats.id_type = records.front().id_type;
    stats.frame_count = records.size();
    stats.first_timestamp_us = records.front().timestamp_us;
    stats.last_timestamp_us = records.back().timestamp_us;

    stats.profile.can_id = can_id;
    stats.profile.id_type = stats.id_type;

    for (const auto& record : records) {
        stats.profile.allowed_dlc.insert(record.dlc);
    }

    std::vector<uint64_t> deltas;
    deltas.reserve(records.size() > 0 ? records.size() - 1 : 0);

    for (std::size_t i = 1; i < records.size(); ++i) {
        deltas.push_back(records[i].timestamp_us - records[i - 1].timestamp_us);
    }

    std::sort(deltas.begin(), deltas.end());
    stats.median_delta_us = median_value(deltas);
    stats.p05_delta_us = percentile_floor(deltas, 5);
    stats.p95_delta_us = percentile_floor(deltas, 95);

    const uint64_t window_us = static_cast<uint64_t>(options.window_ms) * 1000ULL;
    stats.max_count_per_100ms = max_count_in_window_us(records, window_us);

    const double margin = std::max(2.0, std::ceil(
        static_cast<double>(stats.max_count_per_100ms) * options.rate_margin_ratio));
    if (!std::isfinite(margin) ||
        margin > static_cast<double>(std::numeric_limits<int>::max() - stats.max_count_per_100ms)) {
        throw std::runtime_error("computed rate limit exceeds int range");
    }
    const auto rate_margin = static_cast<int>(margin);

    stats.profile.rate_limit_100ms = stats.max_count_per_100ms + rate_margin;

    const bool enough_frames = stats.frame_count >= options.min_periodic_frames;
    const bool has_deltas = !deltas.empty();
    const bool median_ok = stats.median_delta_us <= options.periodic_median_max_us;

    const double jitter_ratio =
        static_cast<double>(stats.p95_delta_us) /
        static_cast<double>(std::max<uint64_t>(stats.p05_delta_us, 1ULL));

    const bool jitter_ok = jitter_ratio <= options.periodic_jitter_ratio_max;

    stats.profile.periodic = enough_frames && has_deltas && median_ok && jitter_ok;

    if (stats.profile.periodic) {
        stats.profile.period_min_us = scaled_period(
            stats.p05_delta_us, 1.0 - options.period_margin_ratio, false);
        stats.profile.period_max_us = scaled_period(
            stats.p95_delta_us, 1.0 + options.period_margin_ratio, true);
    } else {
        stats.profile.period_min_us = 0;
        stats.profile.period_max_us = 0;
    }

    compute_fixed_bytes(records, stats.profile.fixed_mask, stats.profile.fixed_value);

    stats.profile.ignore_mask.fill(0);
    stats.profile.max_identical_payload_run = compute_max_identical_payload_run(records);

    return stats;
}

}  // namespace

BaselineProfile build_baseline_profile(
    const std::vector<CanFrameRecord>& records,
    const std::string& benign_source,
    const BaselineBuildOptions& options
) {
    validate_options(options);
    if (records.empty()) {
        throw std::runtime_error("cannot build baseline profile from empty CAN log");
    }
    if (records.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("too many frames for v1 profile counters");
    }
    validate_metadata_text(benign_source);

    BaselineProfile baseline;
    baseline.created_utc = format_utc_now();
    baseline.benign_source = benign_source;
    baseline.benign_source_sha256 = sha256_file(benign_source);
    baseline.window_ms = options.window_ms;
    baseline.period_margin_ratio = options.period_margin_ratio;
    baseline.rate_margin_ratio = options.rate_margin_ratio;

    std::map<uint32_t, std::vector<CanFrameRecord>> grouped_records;

    for (const auto& record : records) {
        validate_record(record);
        auto& group = grouped_records[record.can_id];
        if (!group.empty() && group.front().id_type != record.id_type) {
            throw std::runtime_error("same numeric CAN ID uses both standard and extended types: " +
                                     format_can_id(record.can_id));
        }
        group.push_back(record);
    }

    for (auto& item : grouped_records) {
        baseline.entries.push_back(
            build_id_profile_stats(item.first, item.second, options)
        );
    }

    return baseline;
}

namespace {

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    return value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
}

unsigned hex_digit(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<unsigned>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<unsigned>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<unsigned>(value - 'A' + 10);
    }
    throw std::runtime_error("invalid hexadecimal digit");
}

uint64_t unsigned_number(const std::string& value, uint64_t maximum) {
    if (value.empty()) {
        throw std::runtime_error("empty numeric value");
    }
    uint64_t number = 0;
    for (const auto digit : value) {
        if (digit < '0' || digit > '9') {
            throw std::runtime_error("expected an unsigned decimal integer");
        }
        const auto amount = static_cast<uint64_t>(digit - '0');
        if (amount > maximum || number > (maximum - amount) / 10) {
            throw std::runtime_error("numeric value out of range");
        }
        number = number * 10 + amount;
    }
    return number;
}

uint32_t section_can_id(const std::string& value) {
    if (value.size() < 8 || value.compare(0, 6, "[id:0x") != 0 || value.back() != ']') {
        throw std::runtime_error("override section must be [id:0xHEX]");
    }
    uint32_t id = 0;
    for (std::size_t i = 6; i + 1 < value.size(); ++i) {
        const auto digit = hex_digit(value[i]);
        if (id > (0x1FFFFFFFU - digit) / 16) {
            throw std::runtime_error("override CAN ID exceeds 29 bits");
        }
        id = id * 16 + digit;
    }
    return id;
}

std::array<uint8_t, 8> byte_array(const std::string& value) {
    if (value.size() != 16) {
        throw std::runtime_error("byte mask/value must contain exactly 16 hexadecimal digits");
    }
    std::array<uint8_t, 8> result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = static_cast<uint8_t>(hex_digit(value[2 * i]) * 16 + hex_digit(value[2 * i + 1]));
    }
    return result;
}

std::set<uint8_t> dlc_set(const std::string& value) {
    std::set<uint8_t> result;
    std::size_t start = 0;
    while (true) {
        const auto comma = value.find(',', start);
        const auto dlc = static_cast<uint8_t>(unsigned_number(
            trim(value.substr(start, comma == std::string::npos ? comma : comma - start)), 8));
        if (!result.insert(dlc).second) {
            throw std::runtime_error("duplicate DLC in allowed_dlc");
        }
        if (comma == std::string::npos) {
            break;
        }
        start = comma + 1;
    }
    return result;
}

void apply_policy_value(IdProfile& profile, const std::string& key, const std::string& value) {
    if (key == "id_type") {
        if (value != id_type_to_string(profile.id_type)) {
            throw std::runtime_error("id_type override must match the observed CAN ID type");
        }
    } else if (key == "allowed_dlc") {
        profile.allowed_dlc = dlc_set(value);
    } else if (key == "periodic") {
        profile.periodic = unsigned_number(value, 1) != 0;
    } else if (key == "period_min_us") {
        profile.period_min_us = unsigned_number(value, std::numeric_limits<uint64_t>::max());
    } else if (key == "period_max_us") {
        profile.period_max_us = unsigned_number(value, std::numeric_limits<uint64_t>::max());
    } else if (key == "rate_limit_100ms" || key == "max_identical_payload_run") {
        const auto parsed = static_cast<int>(unsigned_number(value, std::numeric_limits<int>::max()));
        if (parsed == 0) {
            throw std::runtime_error(key + " must be positive");
        }
        if (key == "rate_limit_100ms") {
            profile.rate_limit_100ms = parsed;
        } else {
            profile.max_identical_payload_run = parsed;
        }
    } else if (key == "fixed_mask") {
        profile.fixed_mask = byte_array(value);
    } else if (key == "fixed_value") {
        profile.fixed_value = byte_array(value);
    } else if (key == "ignore_mask") {
        profile.ignore_mask = byte_array(value);
    } else {
        throw std::runtime_error("unknown or non-overridable key: " + key);
    }
}

}  // namespace

void apply_baseline_overrides(BaselineProfile& baseline, const std::string& override_path) {
    validate_metadata_text(override_path);
    const auto source_hash = sha256_file(override_path);
    std::ifstream input(override_path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open profile override file: " + override_path);
    }

    auto candidate = baseline;
    std::map<uint32_t, std::set<std::string>> sections;
    IdProfileStats* current = nullptr;
    std::size_t line_number = 0;
    std::string line;
    try {
        while (std::getline(input, line)) {
            ++line_number;
            if (line_number == 1 && line.compare(0, 3, "\xEF\xBB\xBF") == 0) {
                line.erase(0, 3);
            }
            line = trim(line);
            if (line.empty() || line.front() == '#' || line.front() == ';') {
                continue;
            }
            if (line.front() == '[') {
                const auto id = section_can_id(line);
                if (!sections.emplace(id, std::set<std::string>{}).second) {
                    throw std::runtime_error("duplicate override ID section");
                }
                const auto match = std::find_if(candidate.entries.begin(), candidate.entries.end(),
                    [id](const IdProfileStats& entry) { return entry.can_id == id; });
                if (match == candidate.entries.end()) {
                    throw std::runtime_error("override ID was not observed in benign log");
                }
                current = &*match;
                continue;
            }

            const auto equals = line.find('=');
            if (!current || equals == std::string::npos) {
                throw std::runtime_error("expected key=value inside an ID section");
            }
            const auto key = trim(line.substr(0, equals));
            const auto value = trim(line.substr(equals + 1));
            if (!sections.at(current->can_id).insert(key).second) {
                throw std::runtime_error("duplicate override key: " + key);
            }
            apply_policy_value(current->profile, key, value);
        }
    } catch (const std::exception& error) {
        throw std::runtime_error("profile override " + override_path + ":" +
                                 std::to_string(line_number) + ": " + error.what());
    }
    if (input.bad() || !input.eof()) {
        throw std::runtime_error("failed to read profile override file: " + override_path);
    }
    if (sections.empty()) {
        throw std::runtime_error("profile override contains no ID sections");
    }
    for (auto& entry : candidate.entries) {
        const auto section = sections.find(entry.can_id);
        if (section == sections.end()) {
            continue;
        }
        const auto& keys = section->second;
        if (keys.empty()) {
            throw std::runtime_error("empty override section for " + format_can_id(entry.can_id));
        }
        auto& profile = entry.profile;
        if (!profile.periodic) {
            if ((keys.count("period_min_us") && profile.period_min_us != 0) ||
                (keys.count("period_max_us") && profile.period_max_us != 0)) {
                throw std::runtime_error("nonperiodic ID cannot have a nonzero period range");
            }
            profile.period_min_us = 0;
            profile.period_max_us = 0;
        } else if (profile.period_min_us > profile.period_max_us) {
            throw std::runtime_error("period_min_us cannot exceed period_max_us");
        }
    }
    if (sha256_file(override_path) != source_hash) {
        throw std::runtime_error("profile override changed while being read");
    }
    candidate.override_source = override_path;
    candidate.override_source_sha256 = source_hash;
    baseline = std::move(candidate);
}

void write_baseline_ini(
    const BaselineProfile& baseline,
    const std::string& output_path
) {
    validate_metadata_text(baseline.benign_source);
    validate_metadata_text(baseline.override_source);
    std::ofstream output(output_path);
    if (!output) {
        throw std::runtime_error("failed to open baseline output file: " + output_path);
    }
    output.imbue(std::locale::classic());

    output << "[global]\n";
    output << "window_ms=" << baseline.window_ms << "\n";
    output << "created_utc=" << baseline.created_utc << "\n";
    output << "benign_source=" << baseline.benign_source << "\n";
    output << "benign_source_sha256=" << baseline.benign_source_sha256 << "\n";
    if (!baseline.override_source.empty()) {
        output << "override_source=" << baseline.override_source << "\n";
        output << "override_source_sha256=" << baseline.override_source_sha256 << "\n";
    }
    output << "period_margin_ratio=" << baseline.period_margin_ratio << "\n";
    output << "rate_margin_ratio=" << baseline.rate_margin_ratio << "\n";

    for (const auto& entry : baseline.entries) {
        output << "\n";
        output << "[id:" << format_can_id(entry.can_id) << "]\n";
        output << "id_type=" << id_type_to_string(entry.id_type) << "\n";
        output << "frame_count=" << entry.frame_count << "\n";
        output << "first_timestamp_us=" << entry.first_timestamp_us << "\n";
        output << "last_timestamp_us=" << entry.last_timestamp_us << "\n";
        output << "allowed_dlc=" << format_allowed_dlc(entry.profile.allowed_dlc) << "\n";
        output << "periodic=" << (entry.profile.periodic ? 1 : 0) << "\n";
        output << "median_delta_us=" << entry.median_delta_us << "\n";
        output << "p05_delta_us=" << entry.p05_delta_us << "\n";
        output << "p95_delta_us=" << entry.p95_delta_us << "\n";
        output << "period_min_us=" << entry.profile.period_min_us << "\n";
        output << "period_max_us=" << entry.profile.period_max_us << "\n";
        output << "max_count_per_100ms=" << entry.max_count_per_100ms << "\n";
        output << "rate_limit_100ms=" << entry.profile.rate_limit_100ms << "\n";
        output << "fixed_mask=" << format_byte_array_hex(entry.profile.fixed_mask) << "\n";
        output << "fixed_value=" << format_byte_array_hex(entry.profile.fixed_value) << "\n";
        output << "ignore_mask=" << format_byte_array_hex(entry.profile.ignore_mask) << "\n";
        output << "max_identical_payload_run=" << entry.profile.max_identical_payload_run << "\n";
    }
    finish_output(output, output_path);
}

void write_profile_summary(
    const BaselineProfile& baseline,
    const std::string& output_path
) {
    std::ofstream output(output_path);
    if (!output) {
        throw std::runtime_error("failed to open profile summary file: " + output_path);
    }
    output.imbue(std::locale::classic());

    output << "# CANSecLab-Low Baseline Profile Summary\n\n";

    output << "## Metadata\n\n";
    output << "- Created UTC: " << baseline.created_utc << "\n";
    output << "- Benign source: `" << baseline.benign_source << "`\n";
    output << "- Benign source SHA-256: `" << baseline.benign_source_sha256 << "`\n";
    if (!baseline.override_source.empty()) {
        output << "- Override source: `" << baseline.override_source << "`\n";
        output << "- Override source SHA-256: `" << baseline.override_source_sha256 << "`\n";
    }
    output << "- Window: " << baseline.window_ms << " ms\n";
    output << "- Period margin ratio: " << baseline.period_margin_ratio << "\n";
    output << "- Rate margin ratio: " << baseline.rate_margin_ratio << "\n";
    output << "- Unique CAN IDs: " << baseline.entries.size() << "\n\n";

    output << "## ID Summary\n\n";
    output << "| CAN ID | Type | Frames | DLC | Periodic | Median Δ us | p05 Δ us | p95 Δ us | Rate Limit / 100ms | Fixed Mask | Max Identical Run |\n";
    output << "|---|---|---:|---|---:|---:|---:|---:|---:|---|---:|\n";

    for (const auto& entry : baseline.entries) {
        output << "| "
               << format_can_id(entry.can_id)
               << " | "
               << id_type_to_string(entry.id_type)
               << " | "
               << entry.frame_count
               << " | "
               << format_allowed_dlc(entry.profile.allowed_dlc)
               << " | "
               << (entry.profile.periodic ? 1 : 0)
               << " | "
               << entry.median_delta_us
               << " | "
               << entry.p05_delta_us
               << " | "
               << entry.p95_delta_us
               << " | "
               << entry.profile.rate_limit_100ms
               << " | "
               << format_byte_array_hex(entry.profile.fixed_mask)
               << " | "
               << entry.profile.max_identical_payload_run
               << " |\n";
    }

    output << "\n## Effective Policy\n\n";
    output << "| CAN ID | Period Min us | Period Max us | Observed Max / 100ms | Fixed Value | Ignore Mask |\n";
    output << "|---|---:|---:|---:|---|---|\n";
    for (const auto& entry : baseline.entries) {
        output << "| " << format_can_id(entry.can_id)
               << " | " << entry.profile.period_min_us
               << " | " << entry.profile.period_max_us
               << " | " << entry.max_count_per_100ms
               << " | " << format_byte_array_hex(entry.profile.fixed_value)
               << " | " << format_byte_array_hex(entry.profile.ignore_mask) << " |\n";
    }

    output << "\n## Notes\n\n";
    output << "- `periodic=1` means the ID passed the current periodicity heuristic.\n";
    output << "- `fixed_mask` marks bytes that stayed constant across all benign frames for that CAN ID.\n";
    output << "- Percentiles use the sorted delta at floor(p * (n - 1)); an even-sized median is rounded down.\n";
    output << "- Rate counts use a half-open 100 ms window: frames exactly 100 ms apart are not counted together.\n";
    output << "- Equal timestamps preserve input order for identical-payload runs; DLC is part of payload identity.\n";
    output << "- `ignore_mask` defaults to zero. Explicit overrides change policy values, not observed statistics.\n";
    output << "- This profile is generated from benign traffic only and should be treated as a validation baseline, not a production IDS policy.\n";
    finish_output(output, output_path);
}

}  // namespace cansec
