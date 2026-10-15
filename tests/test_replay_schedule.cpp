#include "cansec/replay.hpp"

#include <cmath>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

int failures = 0;
int checks = 0;

void check(bool condition, const std::string& name) {
    ++checks;
    std::cout << (condition ? "[PASS] " : "[FAIL] ") << name << '\n';
    if (!condition) ++failures;
}

cansec::CanFrameRecord frame(uint64_t timestamp, uint32_t id = 0x100,
                             cansec::IdType type = cansec::IdType::Standard11, uint8_t dlc = 2) {
    cansec::CanFrameRecord record;
    record.timestamp_us = timestamp;
    record.interface_name = "saved-interface";
    record.can_id = id;
    record.id_type = type;
    record.dlc = dlc;
    record.data = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    return record;
}

template <typename Exception>
void expect_error(const std::vector<cansec::CanFrameRecord>& records, long double speed,
                  uint64_t loops, const std::string& context, const std::string& name) {
    try {
        (void)cansec::make_replay_schedule(records, speed, loops);
        check(false, name + " did not throw");
    } catch (const Exception& error) {
        check(std::string(error.what()).find(context) != std::string::npos, name + " with context");
    } catch (const std::exception& error) {
        check(false, name + " raised wrong exception: " + error.what());
    }
}

void test_offsets_and_loops() {
    const std::vector<cansec::CanFrameRecord> records{frame(1000000), frame(1010000), frame(1030000)};
    const auto original = cansec::make_replay_schedule(records);
    check(original.offsets_us == std::vector<uint64_t>{0, 10000, 30000},
          "default speed subtracts the first frame timestamp");
    check(original.loop_count == 1 && original.loop_duration_us == 30000 &&
          original.total_duration_us == 30000 && original.total_frames == 3,
          "default schedule reports one complete loop");
    check(cansec::make_replay_schedule(records, 2.0L).offsets_us == std::vector<uint64_t>{0, 5000, 15000},
          "speed 2 halves relative offsets");
    check(cansec::make_replay_schedule(records, 0.5L).offsets_us == std::vector<uint64_t>{0, 20000, 60000},
          "speed 0.5 doubles relative offsets");

    const auto repeated = cansec::make_replay_schedule(records, 1.0L, 3);
    check(repeated.offsets_us.size() == records.size() && repeated.loop_count == 3 &&
          repeated.total_frames == 9 && repeated.total_duration_us == 90000,
          "three loops are checked without materializing repeated records");
    const uint64_t first_loop_end = repeated.offsets_us.back();
    const uint64_t second_loop_start = repeated.loop_duration_us + repeated.offsets_us.front();
    check(first_loop_end == second_loop_start,
          "consecutive loops share the last and first target without an added gap");

    const auto fractional = cansec::make_replay_schedule({frame(100), frame(101), frame(102), frame(103)}, 2.0L);
    check(fractional.offsets_us == std::vector<uint64_t>{0, 0, 1, 1},
          "fractional microseconds are floored per absolute offset, not per gap");
    const auto thirds = cansec::make_replay_schedule({frame(0), frame(10), frame(20)}, 3.0L, 2);
    check(thirds.offsets_us == std::vector<uint64_t>{0, 3, 6} && thirds.total_duration_us == 12,
          "nonintegral scaled offsets define the repeated span consistently");
    const auto equal = cansec::make_replay_schedule({frame(9), frame(9), frame(9)}, 0.5L, 4);
    check(equal.offsets_us == std::vector<uint64_t>{0, 0, 0} && equal.total_duration_us == 0 && equal.total_frames == 12,
          "equal timestamps and zero-duration loops are valid");
    const auto single = cansec::make_replay_schedule({frame(99)}, 1.0L, std::numeric_limits<uint64_t>::max());
    check(single.total_duration_us == 0 && single.total_frames == std::numeric_limits<uint64_t>::max(),
          "one-frame loop can represent the maximum total frame count without wrap");
    const auto collapsed = cansec::make_replay_schedule(records, std::numeric_limits<long double>::max());
    check(collapsed.offsets_us == std::vector<uint64_t>{0, 0, 0},
          "a large finite speed can collapse all microsecond offsets to zero");
}

void test_frames_and_order() {
    std::vector<cansec::CanFrameRecord> records;
    for (const auto type : {cansec::IdType::Standard11, cansec::IdType::Extended29}) {
        for (const auto id : {0U, type == cansec::IdType::Standard11 ? 0x7FFU : 0x1FFFFFFFU}) {
            for (const auto dlc : {0, 8}) {
                records.push_back(frame(records.size(), id, type, static_cast<uint8_t>(dlc)));
            }
        }
    }
    records.push_back(frame(records.size(), 0x100, cansec::IdType::Extended29, 1));
    const auto original = records;
    const auto schedule = cansec::make_replay_schedule(records);
    check(schedule.total_frames == 9, "standard/extended zero and maximum IDs, low extended ID and DLC 0/8 are valid");
    bool unchanged = true;
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto& before = original[i];
        const auto& after = records[i];
        unchanged = unchanged && before.timestamp_us == after.timestamp_us &&
                    before.interface_name == after.interface_name && before.can_id == after.can_id &&
                    before.id_type == after.id_type && before.dlc == after.dlc && before.data == after.data;
    }
    check(unchanged, "scheduling preserves all original frame fields including unused payload bytes");

    auto invalid = frame(10, 0x800);
    expect_error<std::invalid_argument>({frame(0), invalid}, 1, 1, "frame 2: standard", "oversize standard ID is rejected");
    invalid = frame(10, 0x20000000, cansec::IdType::Extended29);
    expect_error<std::invalid_argument>({frame(0), invalid}, 1, 1, "frame 2: extended", "oversize extended ID is rejected");
    invalid = frame(10, 0x100, static_cast<cansec::IdType>(-1));
    expect_error<std::invalid_argument>({frame(0), invalid}, 1, 1, "frame 2: invalid ID type", "invalid ID enum is rejected");
    invalid = frame(10, 0x100, cansec::IdType::Standard11, 9);
    expect_error<std::invalid_argument>({frame(0), invalid}, 1, 1, "frame 2: DLC", "DLC 9 is rejected before transmission");
    invalid.dlc = 255;
    expect_error<std::invalid_argument>({frame(0), invalid}, 1, 1, "DLC", "maximum byte DLC is rejected");

    auto other_stream = frame(99, 0x200);
    other_stream.interface_name = "other-saved-interface";
    expect_error<std::invalid_argument>({frame(100), other_stream}, 1, 1, "frame 2: timestamp moves backwards",
                                       "global ordering is checked even across IDs and interfaces");
    expect_error<std::invalid_argument>({frame(100), frame(102), frame(101)}, 1, 1, "frame 3: timestamp moves backwards",
                                       "a later backwards timestamp rejects the entire schedule");
}

void test_invalid_parameters_and_overflow() {
    expect_error<std::invalid_argument>({}, 1, 1, "no CAN frames", "empty input is rejected");
    const std::vector<cansec::CanFrameRecord> records{frame(0), frame(100)};
    expect_error<std::invalid_argument>(records, 0, 1, "finite and positive", "zero speed is rejected");
    expect_error<std::invalid_argument>(records, -1, 1, "finite and positive", "negative speed is rejected");
    expect_error<std::invalid_argument>(records, std::numeric_limits<long double>::infinity(), 1,
                                       "finite and positive", "infinite speed is rejected");
    expect_error<std::invalid_argument>(records, -std::numeric_limits<long double>::infinity(), 1,
                                       "finite and positive", "negative infinity speed is rejected");
    expect_error<std::invalid_argument>(records, std::numeric_limits<long double>::quiet_NaN(), 1,
                                       "finite and positive", "NaN speed is rejected");
    expect_error<std::invalid_argument>(records, 1, 0, "loop count", "zero loops are rejected");
    expect_error<std::overflow_error>(records, std::numeric_limits<long double>::min(), 1,
                                     "timestamp offset", "tiny positive speed is rejected when offsets overflow");

    const uint64_t maximum = std::numeric_limits<uint64_t>::max();
    const auto late_epoch = cansec::make_replay_schedule({frame(maximum - 20), frame(maximum - 10), frame(maximum)}, 2);
    check(late_epoch.offsets_us == std::vector<uint64_t>{0, 5, 10},
          "subtracting before scaling preserves small intervals near UINT64_MAX");
    const auto full_span = cansec::make_replay_schedule({frame(0), frame(maximum)});
    check(full_span.offsets_us.back() == maximum && full_span.total_duration_us == maximum,
          "default speed preserves the full uint64 timestamp span exactly");
    expect_error<std::overflow_error>({frame(0), frame(maximum)}, 0.5L, 1,
                                     "timestamp offset", "scaled offset overflow is rejected");
    expect_error<std::overflow_error>({frame(0), frame(maximum)}, 1, 2,
                                     "total duration", "whole-loop duration overflow is rejected");
    expect_error<std::overflow_error>(records, 1, maximum / 2 + 1,
                                     "total frame count", "whole-loop frame count overflow is rejected");
    expect_error<std::overflow_error>({frame(5), frame(5)}, 1, maximum,
                                     "total frame count", "zero span does not bypass total frame count checks");
    const auto boundary = cansec::make_replay_schedule({frame(0), frame(maximum / 2)}, 1, 2);
    check(boundary.total_duration_us == maximum - 1 && boundary.total_frames == 4,
          "largest two-loop duration below the limit is accepted without wrap");
}

template <typename Exception, typename Operation>
void expect_plan_error(Operation operation, const std::string& context, const std::string& name) {
    try {
        (void)operation();
        check(false, name + " did not throw");
    } catch (const Exception& error) {
        check(std::string(error.what()).find(context) != std::string::npos, name + " with context");
    } catch (const std::exception& error) {
        check(false, name + " raised wrong exception: " + error.what());
    }
}

bool same_frame(const cansec::CanFrameRecord& first, const cansec::CanFrameRecord& second) {
    return first.timestamp_us == second.timestamp_us && first.interface_name == second.interface_name &&
           first.can_id == second.can_id && first.id_type == second.id_type &&
           first.dlc == second.dlc && first.data == second.data;
}

class TestFiles {
public:
    TestFiles() {
        const auto token = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        for (int attempt = 0; attempt < 10; ++attempt) {
            root_ = std::filesystem::temp_directory_path() /
                ("cansec-replay-plans-" + token + "-" + std::to_string(attempt));
            if (std::filesystem::create_directory(root_)) return;
        }
        throw std::runtime_error("failed to create a new replay test directory");
    }
    ~TestFiles() {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }
    std::string write(const std::string& name, const std::string& contents) {
        const auto path = (root_ / name).string();
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("failed to open test fixture: " + path);
        output << contents;
        output.close();
        if (!output) throw std::runtime_error("failed to write test fixture: " + path);
        return path;
    }
    std::string path(const std::string& name) const { return (root_ / name).string(); }
    std::string directory() const { return root_.string(); }
    TestFiles(const TestFiles&) = delete;
    TestFiles& operator=(const TestFiles&) = delete;
private:
    std::filesystem::path root_;
};

void test_flood_plan() {
    const auto input = frame(987654321, 0x100, cansec::IdType::Extended29, 2);
    const auto plan = cansec::make_flood_plan(input, 1000, 3);
    check(plan.records.size() == 1 && same_frame(plan.records.front(), input),
          "flood preserves the typed ID, DLC, payload and original frame fields in one record");
    check(plan.schedule.offsets_us == std::vector<uint64_t>{0} && plan.schedule.loop_count == 3 &&
          plan.schedule.loop_duration_us == 1000 && plan.schedule.total_duration_us == 2000 &&
          plan.schedule.total_frames == 3 && plan.initial_delay_us == 0,
          "flood targets 0, 1000 and 2000 us with no wait after the final frame");
    const uint64_t maximum = std::numeric_limits<uint64_t>::max();
    const auto once = cansec::make_flood_plan(input, maximum, 1);
    check(once.schedule.total_duration_us == 0 && once.schedule.total_frames == 1,
          "one flood frame has no interval multiplication or trailing delay");
    const auto huge = cansec::make_flood_plan(input, 1, maximum);
    check(huge.records.size() == 1 && huge.schedule.offsets_us.size() == 1 &&
          huge.schedule.total_frames == maximum && huge.schedule.total_duration_us == maximum - 1,
          "maximum flood count uses constant storage and a checked final target");
    check(cansec::make_flood_plan(input, maximum, 2).schedule.total_duration_us == maximum,
          "flood final target exactly UINT64_MAX is accepted");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_flood_plan(input, 0, 1); },
                                             "interval_us", "zero flood interval is rejected");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_flood_plan(input, 1, 0); },
                                             "count", "zero flood count is rejected");
    expect_plan_error<std::overflow_error>([&] { return cansec::make_flood_plan(input, maximum, 3); },
                                           "total duration", "flood final-target multiplication overflow is rejected");
}

void test_fuzz_plan() {
    const auto base = frame(456, 0x7FF, cansec::IdType::Standard11, 4);
    auto expected = base;
    expected.data[1] = 0xCB;
    expected.data[3] = 0x87;
    const auto plan = cansec::make_fuzz_plan(base, {0, 0xFF, 0, 0xFF}, 10000, 5);
    check(plan.records.size() == 1 && same_frame(plan.records.front(), expected) &&
          plan.schedule.loop_count == 5 && plan.schedule.total_frames == 5,
          "fuzz stores one XOR result for every repeat rather than alternating payloads");
    check(base.data[1] == 0x34 && base.data[3] == 0x78 && plan.records.front().data[4] == base.data[4],
          "fuzz does not mutate the base or unused payload tail");
    check(plan.schedule.offsets_us == std::vector<uint64_t>{0} && plan.schedule.loop_duration_us == 10000 &&
          plan.schedule.total_duration_us == 40000 && plan.initial_delay_us == 0,
          "fuzz timing uses count minus one periods");
    check(same_frame(cansec::make_fuzz_plan(base, {0, 0, 0, 0}, 1, 2).records.front(), base),
          "an all-zero fuzz mask leaves the valid payload unchanged");
    const auto empty = frame(1, 0, cansec::IdType::Extended29, 0);
    check(same_frame(cansec::make_fuzz_plan(empty, {}, 1, 2).records.front(), empty),
          "DLC zero accepts an empty fuzz mask and preserves the extended zero ID");
    auto full = frame(0, 0x1FFFFFFF, cansec::IdType::Extended29, 8);
    auto inverted = full;
    for (auto& byte : inverted.data) byte ^= 0xFF;
    check(same_frame(cansec::make_fuzz_plan(full, std::vector<uint8_t>(8, 0xFF), 1, 2).records.front(), inverted),
          "DLC eight can invert every valid byte of a maximum extended ID");
    for (const auto& mask : {std::vector<uint8_t>{}, std::vector<uint8_t>{0, 0, 0}, std::vector<uint8_t>(5, 0)}) {
        expect_plan_error<std::invalid_argument>([&] { return cansec::make_fuzz_plan(base, mask, 1, 1); },
                                                 "length must equal DLC", "mismatched fuzz mask length is rejected");
    }
    for (const uint8_t invalid_mask : {uint8_t{1}, uint8_t{0x7F}, uint8_t{0xFE}}) {
        expect_plan_error<std::invalid_argument>([&] { return cansec::make_fuzz_plan(base, {0, invalid_mask, 0, 0}, 1, 1); },
                                                 "flip_mask byte 1", "partial-byte fuzz masks are rejected");
    }
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_fuzz_plan(empty, {0}, 1, 1); },
                                             "length must equal DLC", "DLC zero rejects a nonempty fuzz mask");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_fuzz_plan(base, {0, 0, 0, 0}, 0, 1); },
                                             "period_us", "zero fuzz period is rejected");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_fuzz_plan(base, {0, 0, 0, 0}, 1, 0); },
                                             "count", "zero fuzz count is rejected");
    const uint64_t maximum = std::numeric_limits<uint64_t>::max();
    const auto once = cansec::make_fuzz_plan(base, {0, 0, 0, 0}, maximum, 1);
    check(once.schedule.total_duration_us == 0, "a single fuzz frame accepts any positive uint64 period");
    const auto huge = cansec::make_fuzz_plan(base, {0, 0, 0, 0}, 1, maximum);
    check(huge.records.size() == 1 && huge.schedule.total_frames == maximum &&
          huge.schedule.total_duration_us == maximum - 1,
          "maximum fuzz count does not allocate repeated frames");
    expect_plan_error<std::overflow_error>([&] { return cansec::make_fuzz_plan(base, {0, 0, 0, 0}, maximum, 3); },
                                           "total duration", "fuzz final-target multiplication overflow is rejected");
}

void test_injection_frame_validation() {
    const std::vector<cansec::CanFrameRecord> invalid{
        frame(0, 0x800), frame(0, 0x20000000, cansec::IdType::Extended29),
        frame(0, 0x100, static_cast<cansec::IdType>(99)),
        frame(0, 0x100, cansec::IdType::Standard11, 9),
        frame(0, 0x100, cansec::IdType::Standard11, 255)};
    for (const auto& record : invalid) {
        expect_plan_error<std::invalid_argument>([&] { return cansec::make_flood_plan(record, 1, 1); },
                                                 "replay frame 1", "flood rejects invalid ID/type/DLC input");
        expect_plan_error<std::invalid_argument>([&] { return cansec::make_fuzz_plan(record, {}, 1, 1); },
                                                 "replay frame 1", "fuzz validates ID/type/DLC before mask access");
    }
    const std::vector<cansec::CanFrameRecord> valid{
        frame(0, 0, cansec::IdType::Standard11, 0), frame(0, 0x7FF, cansec::IdType::Standard11, 8),
        frame(0, 0, cansec::IdType::Extended29, 0), frame(0, 0x1FFFFFFF, cansec::IdType::Extended29, 8),
        frame(0, 0x100, cansec::IdType::Extended29, 2)};
    for (const auto& record : valid) {
        check(same_frame(cansec::make_flood_plan(record, 1, 2).records.front(), record) &&
              same_frame(cansec::make_fuzz_plan(record, std::vector<uint8_t>(record.dlc, 0), 1, 2).records.front(), record),
              "both injection plans accept boundary typed IDs and DLC without changing frame identity");
    }
}

void test_segment_selection(TestFiles& files) {
    const std::string contents = "# header\r\n\r\n"
        "(10.000000) saved0 100#1234\r\n# between\r\n"
        "(10.010000) saved1 00000100#AB\r\n"
        "(10.020000) saved1 1FFFFFFF#0011223344556677\r\n\r\n"
        "(10.030000) saved0 7FF#";
    const auto path = files.write("physical-lines.log", contents);
    const auto plan = cansec::make_segment_replay_plan(path, 3, 6, 123, 3);
    check(plan.records.size() == 3 && plan.records[0].timestamp_us == 10000000 &&
          plan.records[1].can_id == 0x100 && plan.records[1].id_type == cansec::IdType::Extended29 &&
          plan.records[1].dlc == 1 && plan.records[1].data[0] == 0xAB &&
          plan.records[1].interface_name == "saved1" && plan.records[2].can_id == 0x1FFFFFFF &&
          plan.records[2].dlc == 8 && plan.records[2].data[7] == 0x77,
          "inclusive physical line selection counts CRLF blanks/comments and preserves parsed fields");
    check(plan.schedule.offsets_us == std::vector<uint64_t>{0, 10000, 20000} &&
          plan.schedule.loop_count == 3 && plan.schedule.loop_duration_us == 20000 &&
          plan.schedule.total_frames == 9 && plan.schedule.total_duration_us == 60000 &&
          plan.initial_delay_us == 123000,
          "segment repeats preserve relative timing and keep one initial delay separate");
    check(plan.initial_delay_us + plan.schedule.loop_duration_us + plan.schedule.offsets_us.front() == 143000 &&
          plan.initial_delay_us + plan.schedule.total_duration_us == 183000,
          "segment loop boundaries add no gap and do not repeat the initial delay");
    const auto single = cansec::make_segment_replay_plan(path, 5, 5, 0, 5);
    check(single.records.size() == 1 && single.records[0].id_type == cansec::IdType::Extended29 &&
          single.schedule.total_frames == 5 && single.schedule.total_duration_us == 0,
          "one selected physical line is inclusive and can repeat at the same target");
    const auto last = cansec::make_segment_replay_plan(path, 8, 8, 0, 1);
    check(last.records.size() == 1 && last.records[0].can_id == 0x7FF && last.records[0].dlc == 0,
          "final physical line without a trailing newline is counted");
    std::ifstream input(path, std::ios::binary);
    const std::string after{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    check(after == contents, "segment plan generation leaves the original file unchanged");

    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(path, 0, 3, 0, 1); },
                                             "start_line", "segment start zero is rejected");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(path, 1, 0, 0, 1); },
                                             "end_line", "segment end zero is rejected");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(path, 6, 3, 0, 1); },
                                             "end_line", "reversed physical line bounds are rejected");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(path, 1, 9, 0, 1); },
                                             "end_line exceeds file line count 8", "end beyond the last physical line is rejected");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(path, 1, std::numeric_limits<uint64_t>::max(), 0, 1); },
                                             "end_line", "maximum end line is rejected without line-count wrap");
    for (const auto& bounds : {std::pair<uint64_t, uint64_t>{1, 2}, {4, 4}, {7, 7}}) {
        expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(path, bounds.first, bounds.second, 0, 1); },
                                                 "no CAN frames", "blank/comment-only selected range is rejected");
    }
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(path, 3, 6, 0, 0); },
                                             "repeat", "zero segment repeats are rejected");
    const auto ended = files.write("newline-end.log", "(1.000000) saved0 100#00\n");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(ended, 1, 2, 0, 1); },
                                             "file line count 1", "trailing newline does not create a phantom physical line");
}

void test_segment_full_file_validation(TestFiles& files) {
    struct InvalidFile { const char* name; const char* contents; uint64_t start; uint64_t end; uint64_t bad_line; };
    const std::vector<InvalidFile> invalid{
        {"malformed-before.log", "broken\n(1.000000) saved0 100#00\n", 2, 2, 1},
        {"malformed-after.log", "(1.000000) saved0 100#00\nbroken\n", 1, 1, 2},
        {"dlc-after.log", "(1.000000) saved0 100#00\n(2.000000) saved0 100#000000000000000000\n", 1, 1, 2},
        {"id-before.log", "(1.000000) saved0 20000000#00\n(2.000000) saved0 100#00\n", 2, 2, 1},
        {"backwards-before.log", "(3.000000) saved0 100#00\n(2.000000) saved1 200#11\n(4.000000) saved0 100#22\n", 3, 3, 2},
        {"backwards-after.log", "(2.000000) saved0 100#00\n(1.000000) saved1 00000100#11\n", 1, 1, 2}};
    for (const auto& example : invalid) {
        const auto path = files.write(example.name, example.contents);
        expect_plan_error<std::runtime_error>([&] { return cansec::make_segment_replay_plan(path, example.start, example.end, 0, 1); },
                                              path + ":" + std::to_string(example.bad_line) + ":",
                                              "invalid data outside the selected range is rejected with its actual line");
    }
    const auto ctrl_z = files.write("ctrl-z.log", std::string("(1.000000) saved0 100#00\n") + char(0x1A) + "broken\n");
    expect_plan_error<std::runtime_error>([&] { return cansec::make_segment_replay_plan(ctrl_z, 1, 1, 0, 1); },
                                          ctrl_z + ":2:", "binary input does not hide malformed data after Ctrl-Z on Windows");
    const auto equal = files.write("equal.log", "(1.000000) saved0 100#00\n(1.000000) saved1 00000100#11\n");
    const auto equal_plan = cansec::make_segment_replay_plan(equal, 1, 2, 0, 2);
    check(equal_plan.schedule.total_duration_us == 0 && equal_plan.schedule.total_frames == 4,
          "equal timestamps across saved streams remain valid in segment replay");
    const auto empty = files.write("empty.log", "");
    expect_plan_error<std::invalid_argument>([&] { return cansec::make_segment_replay_plan(empty, 1, 1, 0, 1); },
                                             "file line count 0", "empty file cannot supply a physical line range");
    const auto missing = files.path("missing.log");
    expect_plan_error<std::runtime_error>([&] { return cansec::make_segment_replay_plan(missing, 1, 1, 0, 1); },
                                          missing, "missing segment input is rejected with its path");
    expect_plan_error<std::runtime_error>([&] { return cansec::make_segment_replay_plan(files.directory(), 1, 1, 0, 1); },
                                          files.directory(), "directory input reports an open or read failure");
}

void test_segment_overflow(TestFiles& files) {
    const uint64_t maximum = std::numeric_limits<uint64_t>::max();
    const auto single = files.write("single.log", "(1.000000) saved0 100#00\n");
    const auto huge = cansec::make_segment_replay_plan(single, 1, 1, 0, maximum);
    check(huge.records.size() == 1 && huge.schedule.total_frames == maximum && huge.schedule.total_duration_us == 0,
          "maximum segment repeat count for one frame avoids repeated storage");
    const auto max_delay = cansec::make_segment_replay_plan(single, 1, 1, maximum / 1000, 1);
    check(max_delay.initial_delay_us == maximum - 615 && max_delay.schedule.total_duration_us == 0,
          "largest millisecond delay fitting uint64 microseconds is accepted");
    expect_plan_error<std::overflow_error>([&] { return cansec::make_segment_replay_plan(single, 1, 1, maximum / 1000 + 1, 1); },
                                           "delay_ms", "initial millisecond conversion overflow is rejected");
    const auto exact = files.write("exact-final.log", "(0.000000) saved0 100#00\n(0.000615) saved0 100#11\n");
    const auto exact_plan = cansec::make_segment_replay_plan(exact, 1, 2, maximum / 1000, 1);
    check(exact_plan.initial_delay_us + exact_plan.schedule.total_duration_us == maximum,
          "initial delay plus final offset exactly UINT64_MAX is accepted");
    const auto overflow = files.write("sum-overflow.log", "(0.000000) saved0 100#00\n(0.001000) saved0 100#11\n");
    expect_plan_error<std::overflow_error>([&] { return cansec::make_segment_replay_plan(overflow, 1, 2, maximum / 1000, 1); },
                                           "initial delay plus total duration", "combined delay and schedule overflow is rejected");
    expect_plan_error<std::overflow_error>([&] { return cansec::make_segment_replay_plan(overflow, 1, 2, 0, maximum / 2 + 1); },
                                           "total frame count", "selected frame count times repeats is checked");
    const auto full = files.write("full-span.log", "(0.000000) saved0 100#00\n(18446744073709.551615) saved0 100#11\n");
    expect_plan_error<std::overflow_error>([&] { return cansec::make_segment_replay_plan(full, 1, 2, 0, 2); },
                                           "total duration", "selected full uint64 span cannot repeat twice");
    const auto first_only = cansec::make_segment_replay_plan(full, 1, 1, 0, 2);
    check(first_only.schedule.total_duration_us == 0 && first_only.schedule.total_frames == 2,
          "unselected valid timestamps are checked for order but do not extend the selected schedule");
}

}  // namespace

int main() {
    try {
        test_offsets_and_loops();
        test_frames_and_order();
        test_invalid_parameters_and_overflow();
        test_flood_plan();
        test_fuzz_plan();
        test_injection_frame_validation();
        TestFiles files;
        test_segment_selection(files);
        test_segment_full_file_validation(files);
        test_segment_overflow(files);
    } catch (const std::exception& error) {
        check(false, std::string("unexpected exception: ") + error.what());
    }
    std::cout << checks << " checks; " << failures << " failure(s).\n";
    return failures == 0 ? 0 : 1;
}
