#include "cansec/baseline.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const std::string& name) {
    std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!condition) {
        ++failures;
    }
}

class TemporaryFiles {
public:
    TemporaryFiles() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        root_ = std::filesystem::temp_directory_path() / ("cansec-baseline-test-" + std::to_string(stamp));
        if (!std::filesystem::create_directory(root_)) {
            throw std::runtime_error("cannot create isolated baseline test directory");
        }
    }

    ~TemporaryFiles() {
        std::error_code ignored;
        std::filesystem::remove_all(root_, ignored);
    }

    std::string path(const std::string& name) const { return (root_ / name).string(); }

    std::string write(const std::string& bytes) const {
        const auto filename = path("baseline.ini");
        std::ofstream output(filename, std::ios::binary);
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.close();
        if (!output) {
            throw std::runtime_error("cannot write baseline test fixture");
        }
        return filename;
    }

private:
    std::filesystem::path root_;
};

std::string policy(const std::string& id = "0x7FF", const std::string& type = "standard") {
    return "[id:" + id + "]\n"
           "id_type=" + type + "\n"
           "allowed_dlc=0,3,8\n"
           "periodic=1\n"
           "period_min_us=8000\n"
           "period_max_us=12000\n"
           "rate_limit_100ms=15\n"
           "fixed_mask=00ff00000000ffff\n"
           "fixed_value=01a2b3c405060708\n"
           "ignore_mask=ff00000000000000\n"
           "max_identical_payload_run=4\n";
}

std::string valid_ini() { return "[global]\nwindow_ms=100\n" + policy(); }

std::string change_value(std::string source, const std::string& key, const std::string& value) {
    const auto start = source.find(key + '=');
    if (start == std::string::npos) {
        throw std::runtime_error("test fixture key not found: " + key);
    }
    const auto end = source.find('\n', start);
    source.replace(start, end - start, key + '=' + value);
    return source;
}

std::string remove_key(std::string source, const std::string& key) {
    const auto start = source.find(key + '=');
    if (start == std::string::npos) {
        throw std::runtime_error("test fixture key not found: " + key);
    }
    source.erase(start, source.find('\n', start) - start + 1);
    return source;
}

void reject_file(const std::string& path, const std::string& name,
                 const std::string& expected_context = {}) {
    try {
        cansec::load_baseline_ini(path);
        check(false, name + " did not throw");
    } catch (const std::runtime_error& error) {
        const std::string message = error.what();
        check(message.find(path) != std::string::npos &&
                  (expected_context.empty() || message.find(expected_context) != std::string::npos),
              name + " (error includes file/context)");
    }
}

void reject(const TemporaryFiles& files, const std::string& content,
            const std::string& name, const std::string& context = {}) {
    reject_file(files.write(content), name, context);
}

void test_valid(const TemporaryFiles& files) {
    const auto baseline = cansec::load_baseline_ini(files.write(valid_ini()));
    const auto& entry = baseline.entries.at(0);
    check(baseline.window_ms == 100 && baseline.entries.size() == 1 && entry.can_id == 0x7FF &&
              entry.id_type == cansec::IdType::Standard11,
          "minimal schema loads standard 11-bit maximum ID");
    check(entry.allowed_dlc == std::set<uint8_t>{0, 3, 8} && entry.periodic &&
              entry.period_min_us == 8000 && entry.period_max_us == 12000 &&
              entry.rate_limit_100ms == 15 && entry.max_identical_payload_run == 4,
          "every scalar policy and multiple DLC values survive loading");
    check(entry.fixed_mask == std::array<uint8_t, 8>{0, 255, 0, 0, 0, 0, 255, 255} &&
              entry.fixed_value == std::array<uint8_t, 8>{1, 162, 179, 196, 5, 6, 7, 8} &&
              entry.ignore_mask == std::array<uint8_t, 8>{255, 0, 0, 0, 0, 0, 0, 0},
          "all eight mask/value bytes and lowercase hex are preserved");

    const auto multiple = cansec::load_baseline_ini(files.write(
        valid_ini() + policy("0x00000100", "extended") + policy("0x1FFFFFFF", "extended")));
    check(multiple.entries.size() == 3 && multiple.entries[1].can_id == 0x100 &&
              multiple.entries[1].id_type == cansec::IdType::Extended29 &&
              multiple.entries[2].can_id == 0x1FFFFFFF &&
              multiple.entries[2].id_type == cansec::IdType::Extended29,
          "low numeric extended ID and maximum 29-bit ID retain explicit types");

    std::string with_metadata = "[global]\nwindow_ms=100\n"
        "created_utc=2026-10-09T01:00:00Z\nbenign_source=input=a.log\n"
        "benign_source_sha256=PLACEHOLDER\noverride_source=policy.ini\n"
        "override_source_sha256=informational\nperiod_margin_ratio=0.2\nrate_margin_ratio=0.2\n" + policy();
    with_metadata += "frame_count=35\nfirst_timestamp_us=0\nlast_timestamp_us=340000\n"
                     "median_delta_us=10000\np05_delta_us=10000\np95_delta_us=10000\n"
                     "max_count_per_100ms=10\n";
    const auto metadata = cansec::load_baseline_ini(files.write(with_metadata));
    check(metadata.entries[0].rate_limit_100ms == 15 && metadata.entries[0].period_min_us == 8000,
          "writer metadata keys are accepted");

    std::string decorated = "\xEF\xBB\xBF";
    decorated += " # leading comment\r\n; semicolon comment\r\n\r\n";
    for (const char ch : change_value(valid_ini(), "allowed_dlc", "0, 3, 8")) {
        decorated += ch == '\n' ? "\r\n" : std::string(1, ch);
    }
    check(cansec::load_baseline_ini(files.write(decorated)).entries[0].allowed_dlc.size() == 3,
          "UTF-8 BOM, CRLF, blank lines, whole-line comments and DLC spacing are accepted");

    auto nonperiodic = change_value(valid_ini(), "periodic", "0");
    nonperiodic = change_value(nonperiodic, "period_min_us", "0");
    nonperiodic = change_value(nonperiodic, "period_max_us", "0");
    const auto idle = cansec::load_baseline_ini(files.write(nonperiodic));
    check(!idle.entries[0].periodic && idle.entries[0].period_min_us == 0 &&
              idle.entries[0].period_max_us == 0,
          "nonperiodic zero-range policy is accepted");
    auto boundary = change_value(valid_ini(), "period_min_us", "0");
    boundary = change_value(boundary, "period_max_us", "18446744073709551615");
    boundary = change_value(boundary, "rate_limit_100ms", std::to_string(std::numeric_limits<int>::max()));
    boundary = change_value(boundary, "max_identical_payload_run", std::to_string(std::numeric_limits<int>::max()));
    const auto limits = cansec::load_baseline_ini(files.write(boundary));
    check(limits.entries[0].periodic && limits.entries[0].period_min_us == 0 &&
              limits.entries[0].period_max_us == std::numeric_limits<uint64_t>::max() &&
              limits.entries[0].rate_limit_100ms == std::numeric_limits<int>::max() &&
              limits.entries[0].max_identical_payload_run == std::numeric_limits<int>::max(),
          "periodic minimum zero, UINT64_MAX period and INT_MAX counters are accepted");
    boundary = change_value(boundary, "period_max_us", "0");
    check(cansec::load_baseline_ini(files.write(boundary)).entries[0].period_max_us == 0,
          "periodic zero-zero range remains compatible with generated policy");

    auto no_final_newline = valid_ini();
    no_final_newline.pop_back();
    check(cansec::load_baseline_ini(files.write(no_final_newline)).entries.size() == 1,
          "last policy line need not end in newline");
    check(cansec::load_baseline_ini(files.write(policy() + "[global]\nwindow_ms=100\n")).entries.size() == 1,
          "required global section may follow a complete ID section");
}

void test_structure_errors(const TemporaryFiles& files) {
    reject_file(files.path("missing.ini"), "missing file rejected", "open");
    reject_file(files.path("."), "directory cannot be read as baseline");
    reject(files, "", "empty file rejected", "[global]");
    reject(files, "# comment only\n", "comment-only file rejected", "[global]");
    reject(files, policy(), "global section required", "[global]");
    reject(files, "[global]\nwindow_ms=100\n", "at least one ID required", "ID");
    reject(files, "[global]\n" + policy(), "global window required", "window_ms");
    reject(files, valid_ini() + "[global]\nwindow_ms=100\n", "duplicate global section rejected", "duplicate");
    reject(files, valid_ini() + policy(), "duplicate ID section rejected", "duplicate");
    reject(files, valid_ini() + policy("0x000007ff", "extended"),
           "numeric ID aliases collide even with another type", "duplicate");
    reject(files, "window_ms=100\n" + valid_ini(), "key before any section rejected", ":1");
    reject(files, valid_ini() + "not-an-assignment\n", "missing equals rejected");
    reject(files, valid_ini() + "unknown=1\n", "unknown ID key rejected", "unknown");
    reject(files, "[global]\nwindow_ms=100\nunknown=1\n" + policy(),
           "unknown global key rejected", "unknown");
    reject(files, valid_ini() + "created_utc=x\n", "global metadata not allowed in ID section", "created_utc");
    reject(files, "[global]\nwindow_ms=100\nallowed_dlc=8\n" + policy(),
           "ID key not allowed in global section", "allowed_dlc");
    reject(files, "[global]\nwindow_ms=100\nwindow_ms=100\n" + policy(),
           "duplicate global policy key rejected", "window_ms");
    reject(files, "[global]\nwindow_ms=100\ncreated_utc=a\ncreated_utc=b\n" + policy(),
           "duplicate global metadata key rejected", "created_utc");
    reject(files, valid_ini() + "frame_count=30\nframe_count=30\n",
           "duplicate ID metadata key rejected", "frame_count");

    for (const auto& header : {"[other]", "[id:0x]", "[id:0x123", "[id:123]", "[id:0xXYZ]",
                               "[id:0x20000000]", "[id:0xFFFFFFFFFFFFFFFF]", "[id:0x-1]"}) {
        auto input = valid_ini();
        input.replace(input.find("[id:0x7FF]"), 10, header);
        reject(files, input, std::string("malformed/out-of-range section ") + header);
    }
    reject(files, "[global]\nwindow_ms=100\n" + policy("0x800", "standard"),
           "standard type cannot use 12-bit ID", "id_type");
    reject(files, change_value(valid_ini(), "id_type", "unknown"), "unknown ID type rejected", "id_type");
    reject(files, valid_ini() + '\x1A' + "unknown=1\n",
           "Ctrl-Z does not hide invalid trailing input on Windows", "unknown");
    reject(files, valid_ini() + std::string("\0ignored", 8), "embedded NUL rejected", "NUL");
}

void test_policy_errors(const TemporaryFiles& files) {
    const std::array<const char*, 10> required{{
        "id_type", "allowed_dlc", "periodic", "period_min_us", "period_max_us",
        "rate_limit_100ms", "fixed_mask", "fixed_value", "ignore_mask", "max_identical_payload_run"
    }};
    for (const auto key : required) {
        reject(files, remove_key(valid_ini(), key), std::string("required policy key ") + key, key);
        const auto first = valid_ini();
        const auto start = first.find(std::string(key) + '=');
        const auto field = first.substr(start, first.find('\n', start) - start + 1);
        reject(files, first + field, std::string("duplicate policy key ") + key, key);
    }
    for (const auto& value : {"", "0", "99", "101", "-100", "+100", "100ms", "100.0", "2147483648"}) {
        reject(files, change_value(valid_ini(), "window_ms", value),
               std::string("invalid window ") + value, "window_ms");
    }
    for (const auto& value : {"", "-1", "9", "0,0", "3,,8", "3,", ",3", "3,8junk", "1.0", "+1"}) {
        reject(files, change_value(valid_ini(), "allowed_dlc", value),
               std::string("invalid DLC list ") + value, "allowed_dlc");
    }
    for (const auto& value : {"", "2", "true", "-1", "1junk", "1.0"}) {
        reject(files, change_value(valid_ini(), "periodic", value),
               std::string("invalid periodic flag ") + value, "periodic");
    }
    for (const auto key : {"period_min_us", "period_max_us"}) {
        for (const auto& value : {"", "-1", "+1", "1.0", "12junk", "18446744073709551616"}) {
            reject(files, change_value(valid_ini(), key, value),
                   std::string("invalid ") + key + '=' + value, key);
        }
    }
    reject(files, change_value(valid_ini(), "period_min_us", "12001"),
           "reversed period range rejected", "period_min_us/period_max_us");
    reject(files, change_value(valid_ini(), "periodic", "0"),
           "nonperiodic positive range rejected", "nonperiodic");
    auto nonperiodic_max = change_value(valid_ini(), "periodic", "0");
    nonperiodic_max = change_value(nonperiodic_max, "period_min_us", "0");
    reject(files, nonperiodic_max, "nonperiodic positive maximum rejected", "nonperiodic");
    for (const auto key : {"rate_limit_100ms", "max_identical_payload_run"}) {
        for (const auto& value : {"", "0", "-1", "+1", "1junk", "1.5", "2147483648"}) {
            reject(files, change_value(valid_ini(), key, value),
                   std::string("invalid ") + key + '=' + value, key);
        }
    }
    for (const auto key : {"fixed_mask", "fixed_value", "ignore_mask"}) {
        for (const auto& value : {"", "FF", "FFFFFFFFFFFFFFFFF", "GG00000000000000", "FF FF00000000000"}) {
            reject(files, change_value(valid_ini(), key, value),
                   std::string("invalid byte field ") + key + '=' + value, key);
        }
    }
    reject(files, change_value(valid_ini(), "rate_limit_100ms", "15 # inline comment"),
           "inline comments cannot conceal trailing policy text", "rate_limit_100ms");

    const auto path = files.write(change_value(valid_ini(), "allowed_dlc", "9"));
    try {
        cansec::load_baseline_ini(path);
        check(false, "diagnostic context expected");
    } catch (const std::runtime_error& error) {
        const std::string message = error.what();
        check(message.find(path + ":5") != std::string::npos &&
                  message.find("[id:0x7FF]") != std::string::npos &&
                  message.find("allowed_dlc") != std::string::npos,
              "invalid value reports exact file, line, section and key");
    }
}

}  // namespace

int main() {
    try {
        const TemporaryFiles files;
        test_valid(files);
        test_structure_errors(files);
        test_policy_errors(files);
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] unexpected test exception: " << error.what() << '\n';
        ++failures;
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "test_baseline passed.\n";
    return 0;
}
