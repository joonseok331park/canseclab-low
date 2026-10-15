#include "cansec/logio.hpp"
#include "cansec/profile.hpp"
#include "cansec/sha256.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const std::string& name) {
    if (!condition) {
        std::cerr << "[FAIL] " << name << '\n';
        ++failures;
    } else {
        std::cout << "[PASS] " << name << '\n';
    }
}

template <typename Fn>
void expect_throw(Fn fn, const std::string& name) {
    try {
        fn();
        check(false, name + " did not throw");
    } catch (const std::exception&) {
        check(true, name);
    }
}

class TemporaryFiles {
public:
    TemporaryFiles() {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        directory_ = std::filesystem::temp_directory_path() /
                     ("cansec-profile-test-" + std::to_string(stamp));
        if (!std::filesystem::create_directory(directory_)) {
            throw std::runtime_error("cannot create isolated test directory");
        }
    }

    ~TemporaryFiles() {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    std::string path(const std::string& name) const {
        return (directory_ / name).string();
    }

    std::string write(const std::string& name, const std::string& bytes) const {
        const auto filename = path(name);
        std::ofstream output(filename, std::ios::binary);
        output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        output.close();
        if (!output) {
            throw std::runtime_error("cannot write test fixture");
        }
        return filename;
    }

    cansec::BaselineProfile build(
        const std::vector<cansec::CanFrameRecord>& records,
        const cansec::BaselineBuildOptions& options = {}) const {
        std::string log;
        for (const auto& record : records) {
            log += cansec::format_can_record(record) + '\n';
        }
        return cansec::build_baseline_profile(records, write("input.log", log), options);
    }

private:
    std::filesystem::path directory_;
};

cansec::CanFrameRecord frame(uint64_t timestamp, uint32_t id,
                            std::initializer_list<uint8_t> payload,
                            cansec::IdType type = cansec::IdType::Standard11) {
    cansec::CanFrameRecord record;
    record.timestamp_us = timestamp;
    record.interface_name = "vcan0";
    record.can_id = id;
    record.id_type = type;
    record.dlc = static_cast<uint8_t>(payload.size());
    std::copy(payload.begin(), payload.end(), record.data.begin());
    return record;
}

std::vector<cansec::CanFrameRecord> periodic_frames(std::size_t count, uint64_t period = 10000) {
    std::vector<cansec::CanFrameRecord> records;
    for (std::size_t i = 0; i < count; ++i) {
        records.push_back(frame(1000000 + i * period, 0x100,
                                {static_cast<uint8_t>(i), 0x10, 0, 0, 0, 0, 0, 0}));
    }
    return records;
}

std::string read_text(const std::string& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

void test_sha256(const TemporaryFiles& files) {
    check(cansec::sha256_file(files.write("hash.bin", "")) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "SHA-256 empty vector");
    check(cansec::sha256_file(files.write("hash.bin", "abc")) ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA-256 abc vector");
    check(cansec::sha256_file(files.write("hash.bin",
              "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "SHA-256 two-block padding vector");
    check(cansec::sha256_file(files.write("hash.bin", std::string(1000000, 'a'))) ==
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
          "SHA-256 million-a streaming vector");
    const auto lf_hash = cansec::sha256_file(files.write("hash.bin", "abc\n"));
    const auto crlf_hash = cansec::sha256_file(files.write("hash.bin", "abc\r\n"));
    check(lf_hash != crlf_hash, "SHA-256 preserves original line-ending bytes");
    expect_throw([&] { cansec::sha256_file(files.path("missing.bin")); },
                 "SHA-256 missing input is an error");
    expect_throw([&] { cansec::sha256_file(files.path(".")); },
                 "SHA-256 directory input is an error");
}

void test_calculations(const TemporaryFiles& files) {
    auto records = periodic_frames(35);
    std::reverse(records.begin(), records.end());
    const auto baseline = files.build(records);
    const auto& entry = baseline.entries.at(0);
    check(entry.frame_count == 35 && entry.first_timestamp_us == 1000000 &&
              entry.last_timestamp_us == 1340000,
          "unsorted input is normalized and sample count/range are preserved");
    check(entry.median_delta_us == 10000 && entry.p05_delta_us == 10000 &&
              entry.p95_delta_us == 10000 && entry.profile.periodic,
          "periodic sample statistics match exact 10ms cadence");
    check(entry.profile.period_min_us == 8000 && entry.profile.period_max_us == 12000,
          "default period bounds are 80 to 120 percent");
    check(entry.max_count_per_100ms == 10 && entry.profile.rate_limit_100ms == 12,
          "half-open 100ms window and minimum rate margin");
    check(entry.profile.allowed_dlc == std::set<uint8_t>{8} &&
              entry.profile.fixed_mask == std::array<uint8_t, 8>{0, 255, 255, 255, 255, 255, 255, 255} &&
              entry.profile.fixed_value == std::array<uint8_t, 8>{0, 16, 0, 0, 0, 0, 0, 0} &&
              entry.profile.ignore_mask == std::array<uint8_t, 8>{},
          "rolling counter stays variable while constant bytes become fixed");
    check(entry.profile.max_identical_payload_run == 1,
          "rolling payloads have identical run length one");
    check(baseline.benign_source_sha256 == cansec::sha256_file(baseline.benign_source),
          "baseline records the actual source SHA-256");

    check(!files.build(periodic_frames(29)).entries[0].profile.periodic &&
              files.build(periodic_frames(30)).entries[0].profile.periodic,
          "periodic classification changes at 30 frames");
    check(files.build(periodic_frames(30, 200000)).entries[0].profile.periodic &&
              !files.build(periodic_frames(30, 200001)).entries[0].profile.periodic,
          "periodic median threshold includes exactly 200000us");

    const auto dense = files.build(periodic_frames(35, 5000)).entries[0];
    check(dense.max_count_per_100ms == 20 && dense.profile.rate_limit_100ms == 24,
          "rate margin scales to 20 percent for dense traffic");
    const auto ceil_margin = files.build(periodic_frames(35, 9000)).entries[0];
    check(ceil_margin.max_count_per_100ms == 12 && ceil_margin.profile.rate_limit_100ms == 15,
          "fractional rate margin rounds upward");

    std::vector<cansec::CanFrameRecord> jitter;
    uint64_t timestamp = 0;
    jitter.push_back(frame(timestamp, 0x100, {1}));
    for (int i = 0; i < 30; ++i) {
        timestamp += i < 15 ? 10000 : 25000;
        jitter.push_back(frame(timestamp, 0x100, {1}));
    }
    const auto jitter_limit = files.build(jitter).entries[0];
    check(jitter_limit.profile.periodic && jitter_limit.median_delta_us == 17500 &&
              jitter_limit.p05_delta_us == 10000 && jitter_limit.p95_delta_us == 25000,
          "even median and exact jitter ratio 2.5 are accepted");
    jitter.clear();
    timestamp = 0;
    jitter.push_back(frame(timestamp, 0x100, {1}));
    for (int i = 0; i < 30; ++i) {
        timestamp += i < 15 ? 10000 : 25001;
        jitter.push_back(frame(timestamp, 0x100, {1}));
    }
    check(!files.build(jitter).entries[0].profile.periodic,
          "jitter just above 2.5 disables periodic policy");

    const auto quantiles = files.build({frame(101, 0x100, {1}), frame(0, 0x100, {1}),
                                      frame(5, 0x100, {1}), frame(1, 0x100, {1})}).entries[0];
    check(quantiles.median_delta_us == 4 && quantiles.p05_delta_us == 1 &&
              quantiles.p95_delta_us == 4,
          "small-sample percentiles use floor of p times n-minus-one");

    const auto boundaries = files.build({frame(0, 0x100, {1}), frame(99999, 0x100, {1}),
                                        frame(100000, 0x100, {1})}).entries[0];
    check(boundaries.max_count_per_100ms == 2,
          "frame exactly 100ms old expires from rate window");
    const auto same_time = files.build({frame(5, 0x100, {1}), frame(5, 0x100, {1}),
                                       frame(5, 0x100, {2}), frame(5, 0x100, {1})}).entries[0];
    check(same_time.max_count_per_100ms == 4 && same_time.median_delta_us == 0 &&
              same_time.profile.max_identical_payload_run == 2,
          "duplicate timestamps retain all frames and stable payload order");

    const auto mixed_dlc = files.build({frame(0, 0x101, {5, 7}), frame(10, 0x101, {5}),
                                       frame(20, 0x101, {5})}).entries[0];
    check(mixed_dlc.profile.allowed_dlc == std::set<uint8_t>{1, 2} &&
              mixed_dlc.profile.fixed_mask == std::array<uint8_t, 8>{255, 0, 0, 0, 0, 0, 0, 0} &&
              mixed_dlc.profile.max_identical_payload_run == 2,
          "mixed DLC only fixes bytes present in every frame and splits payload runs");
    const auto zero_dlc = files.build({frame(0, 0x102, {}), frame(10, 0x102, {})}).entries[0];
    check(zero_dlc.profile.allowed_dlc == std::set<uint8_t>{0} &&
              zero_dlc.profile.fixed_mask == std::array<uint8_t, 8>{} &&
              zero_dlc.profile.max_identical_payload_run == 2,
          "zero-DLC frames have no fixed bytes");
    const auto single = files.build({frame(500, 0x123, {3, 4})}).entries[0];
    check(!single.profile.periodic && single.median_delta_us == 0 &&
              single.profile.period_min_us == 0 && single.profile.period_max_us == 0 &&
              single.max_count_per_100ms == 1 && single.profile.rate_limit_100ms == 3,
          "single frame produces nonperiodic zero-delta policy");

    const auto grouped = files.build({frame(0, 0x1ABCDEFF, {1}, cansec::IdType::Extended29),
                                     frame(0, 0x100, {1}), frame(10, 0x100, {1})});
    check(grouped.entries.size() == 2 && grouped.entries[0].can_id == 0x100 &&
              grouped.entries[1].id_type == cansec::IdType::Extended29 &&
              grouped.entries[0].frame_count == 2 && grouped.entries[1].frame_count == 1,
          "standard and extended IDs are independently grouped in numeric order");
    const auto low_extended = files.build({frame(0, 0x100, {1}, cansec::IdType::Extended29)});
    check(low_extended.entries[0].id_type == cansec::IdType::Extended29,
          "low numeric extended ID preserves its explicit type");
    const auto huge = files.build({frame(0, 0x100, {1}),
                                  frame(std::numeric_limits<uint64_t>::max() / 2, 0x100, {1}),
                                  frame(std::numeric_limits<uint64_t>::max(), 0x100, {1})}).entries[0];
    check(huge.median_delta_us == std::numeric_limits<uint64_t>::max() / 2,
          "median calculation remains correct near timestamp capacity");
}

void test_input_errors(const TemporaryFiles& files) {
    const auto source = files.write("source.log", "fixture");
    const auto valid = periodic_frames(35);
    expect_throw([&] { cansec::build_baseline_profile({}, source); }, "empty log is rejected");
    expect_throw([&] { cansec::build_baseline_profile(valid, files.path("absent.log")); },
                 "missing source cannot yield a claimed hash");
    expect_throw([&] { files.build({frame(0, 0x100, {1}),
                                   frame(10, 0x100, {1}, cansec::IdType::Extended29)}); },
                 "mixed standard/extended use of the same numeric ID is rejected");

    auto malformed = frame(0, 0x100, {1});
    malformed.dlc = 9;
    expect_throw([&] { cansec::build_baseline_profile({malformed}, source); }, "invalid DLC is rejected");
    malformed = frame(0, 0x800, {1});
    expect_throw([&] { cansec::build_baseline_profile({malformed}, source); },
                 "standard ID exceeding 11 bits is rejected");
    malformed = frame(0, 0x20000000, {1}, cansec::IdType::Extended29);
    expect_throw([&] { cansec::build_baseline_profile({malformed}, source); },
                 "extended ID exceeding 29 bits is rejected");
    malformed = frame(0, 0x100, {1}, static_cast<cansec::IdType>(99));
    expect_throw([&] { cansec::build_baseline_profile({malformed}, source); },
                 "unknown ID type is rejected");

    cansec::BaselineBuildOptions options;
    options.window_ms = 0;
    expect_throw([&] { cansec::build_baseline_profile(valid, source, options); },
                 "invalid rate window is rejected");
    options.window_ms = 200;
    expect_throw([&] { cansec::build_baseline_profile(valid, source, options); },
                 "non-100ms window cannot silently change per-100ms fields");
    options = {};
    options.period_margin_ratio = -0.1;
    expect_throw([&] { cansec::build_baseline_profile(valid, source, options); },
                 "negative period margin is rejected");
    options.period_margin_ratio = 1.1;
    expect_throw([&] { cansec::build_baseline_profile(valid, source, options); },
                 "period margin above one is rejected");
    options = {};
    options.rate_margin_ratio = std::numeric_limits<double>::quiet_NaN();
    expect_throw([&] { cansec::build_baseline_profile(valid, source, options); },
                 "nonfinite rate margin is rejected");
    options.rate_margin_ratio = std::numeric_limits<double>::max();
    expect_throw([&] { cansec::build_baseline_profile(valid, source, options); },
                 "rate-limit arithmetic overflow is rejected");
    options = {};
    options.min_periodic_frames = 1;
    expect_throw([&] { cansec::build_baseline_profile(valid, source, options); },
                 "periodic classification requires at least two frames");
    options = {};
    options.min_periodic_frames = 2;
    options.periodic_median_max_us = std::numeric_limits<uint64_t>::max();
    expect_throw([&] {
        cansec::build_baseline_profile({frame(0, 0x100, {1}),
                                      frame(std::numeric_limits<uint64_t>::max(), 0x100, {1})},
                                      source, options);
    }, "period-range overflow is rejected before integer conversion");
}

void test_overrides_and_output(const TemporaryFiles& files) {
    auto baseline = files.build(periodic_frames(35));
    const auto original = baseline;
    const auto override_path = files.write("override.ini",
        "# Explicit policy edits\n[id:0x100]\n"
        "id_type=standard\nallowed_dlc=7,8\nperiodic=1\n"
        "period_min_us=7000\nperiod_max_us=13000\nrate_limit_100ms=15\n"
        "fixed_mask=00FF000000000000\nfixed_value=0010000000000000\n"
        "ignore_mask=FF00000000000000\nmax_identical_payload_run=4\n");
    cansec::apply_baseline_overrides(baseline, override_path);
    const auto& entry = baseline.entries[0];
    check(entry.profile.allowed_dlc == std::set<uint8_t>{7, 8} &&
              entry.profile.period_min_us == 7000 && entry.profile.period_max_us == 13000 &&
              entry.profile.rate_limit_100ms == 15 && entry.profile.fixed_mask[2] == 0 &&
              entry.profile.fixed_value[1] == 16 && entry.profile.ignore_mask[0] == 255 &&
              entry.profile.max_identical_payload_run == 4 && entry.frame_count == 35 &&
              entry.max_count_per_100ms == 10,
          "explicit overrides change policy and preserve observed statistics");
    check(baseline.override_source == override_path &&
              baseline.override_source_sha256 == cansec::sha256_file(override_path),
          "override provenance records actual file SHA-256");

    const auto ini_path = files.path("baseline.ini");
    const auto summary_path = files.path("summary.md");
    cansec::write_baseline_ini(baseline, ini_path);
    cansec::write_profile_summary(baseline, summary_path);
    const auto ini = read_text(ini_path);
    const auto summary = read_text(summary_path);
    check(ini.find("[id:0x100]\n") != std::string::npos &&
              ini.find("benign_source_sha256=" + baseline.benign_source_sha256) != std::string::npos &&
              ini.find("override_source_sha256=" + baseline.override_source_sha256) != std::string::npos &&
              ini.find("allowed_dlc=7,8\n") != std::string::npos &&
              ini.find("ignore_mask=FF00000000000000\n") != std::string::npos,
          "INI contains effective policy and both exact source hashes");
    check(summary.find(baseline.benign_source_sha256) != std::string::npos &&
              summary.find(baseline.override_source_sha256) != std::string::npos &&
              summary.find("| 0x100 | 7000 | 13000 | 10 |") != std::string::npos,
          "summary connects source hashes to observed counts and effective period bounds");
    expect_throw([&] { cansec::write_baseline_ini(baseline, files.path("absent/baseline.ini")); },
                 "missing output directory is reported");
    expect_throw([&] { cansec::write_profile_summary(baseline, files.path(".")); },
                 "summary cannot be written to a directory");
#if defined(__linux__)
    expect_throw([&] { cansec::write_baseline_ini(baseline, "/dev/full"); },
                 "late INI write failures are reported");
    expect_throw([&] { cansec::write_profile_summary(baseline, "/dev/full"); },
                 "late summary write failures are reported");
#endif

    baseline = original;
    cansec::apply_baseline_overrides(baseline,
        files.write("override.ini", "[id:0x100]\nperiodic=0\n"));
    check(!baseline.entries[0].profile.periodic && baseline.entries[0].profile.period_min_us == 0 &&
              baseline.entries[0].profile.period_max_us == 0,
          "disabling periodic policy clears its previous computed range");

    const std::vector<std::string> invalid_overrides = {
        "# no sections\n",
        "[global]\nwindow_ms=100\n",
        "[id:0x999]\nperiodic=0\n",
        "[id:0x100]\n",
        "[id:0x100]\nunknown=1\n",
        "[id:0x100]\nallowed_dlc=7\nunknown=1\n",
        "[id:0x100]\nframe_count=3\n",
        "[id:0x100]\nrate_limit_100ms=15\nrate_limit_100ms=16\n",
        "[id:0x100]\nperiodic=0\n[id:0x0100]\nperiodic=1\n",
        "[id:0x100]\nid_type=extended\n",
        "[id:0x100]\nallowed_dlc=9\n",
        "[id:0x100]\nallowed_dlc=8,\n",
        "[id:0x100]\nallowed_dlc=8,8\n",
        "[id:0x100]\nperiodic=2\n",
        "[id:0x100]\nrate_limit_100ms=-1\n",
        "[id:0x100]\nrate_limit_100ms=2147483648\n",
        "[id:0x100]\nmax_identical_payload_run=0\n",
        "[id:0x100]\nfixed_mask=FF\n",
        "[id:0x100]\nignore_mask=GG00000000000000\n",
        "[id:0x100]\nperiod_min_us=13000\nperiod_max_us=7000\n",
        "[id:0x100]\nperiodic=0\nperiod_min_us=1\n",
        "[id:0x100]\nperiod_max_us=18446744073709551616\n",
        std::string("[id:0x100]\nrate_limit_100ms=15\n") + '\x1A' + "invalid=x\n"
    };
    cansec::write_baseline_ini(original, files.path("original.ini"));
    const auto original_ini = read_text(files.path("original.ini"));
    bool all_unchanged = true;
    for (std::size_t i = 0; i < invalid_overrides.size(); ++i) {
        baseline = original;
        const auto invalid_path = files.write("invalid.ini", invalid_overrides[i]);
        expect_throw([&] { cansec::apply_baseline_overrides(baseline, invalid_path); },
                     "malformed override case " + std::to_string(i + 1) + " is rejected");
        cansec::write_baseline_ini(baseline, files.path("unchanged.ini"));
        all_unchanged = all_unchanged && read_text(files.path("unchanged.ini")) == original_ini;
    }
    check(all_unchanged, "malformed overrides leave every serialized policy field unchanged");
}

}  // namespace

int main() {
    try {
        const TemporaryFiles files;
        test_sha256(files);
        test_calculations(files);
        test_input_errors(files);
        test_overrides_and_output(files);
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] unexpected test exception: " << error.what() << '\n';
        ++failures;
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed.\n";
        return 1;
    }
    std::cout << "test_profile passed.\n";
    return 0;
}
