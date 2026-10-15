#include "cansec/logio.hpp"
#include "cansec/replay.hpp"

#if defined(__linux__)
#include "cansec/socketcan.hpp"
#include <csignal>
#include <ctime>
#endif

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <iostream>
#include <limits>
#include <locale>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace {

struct Options {
    std::string mode;
    std::string interface_name;
    std::string input_path;
    std::string id;
    std::string data;
    std::string flip_mask;
    long double speed = 1.0L;
    uint64_t loop_count = 1;
    uint64_t interval_us = 0;
    uint64_t count = 0;
    uint64_t start_line = 0;
    uint64_t end_line = 0;
    uint64_t delay_ms = 0;
    uint64_t repeat = 0;
};

bool supported_mode(const std::string& mode) {
    return mode == "normal" || mode == "flood" || mode == "replay" || mode == "fuzz";
}

void print_usage() {
    std::cerr
        << "Usage: cansec-replay normal --if IFACE --in FILE [--speed 1.0] [--loop 1]\n"
        << "       cansec-replay flood --if IFACE --id HEX --data HEX --interval-us N --count N\n"
        << "       cansec-replay replay --if IFACE --in FILE --start-line N --end-line N --delay-ms N --repeat N\n"
        << "       cansec-replay fuzz --if IFACE --id HEX --base-data HEX --period-us N --count N --flip-mask HEX\n"
        << "\n"
        << "  --speed X        playback speed multiplier (> 0)\n"
        << "  --loop N         play the whole log N times\n"
        << "  --start-line N   first/last file line to replay (1-based, comment and blank lines count)\n"
        << "  --end-line N\n"
        << "  --delay-ms N     wait once before the first frame\n"
        << "  --flip-mask HEX  one 00 or FF byte per data byte, XORed into --base-data\n"
        << "\n"
        << "IDs are hex; 8 digits or a value above 7FF means an extended ID.\n"
        << "Normal replay requires Linux; so do flood, replay and fuzz. Ctrl+C stops sending.\n";
}

std::string value_argument(int& index, int argc, char** argv,
                           const std::string& description, bool allow_empty = false) {
    const std::string option = argv[index];
    if (index + 1 >= argc || (!allow_empty && std::string(argv[index + 1]).empty()) ||
        std::string(argv[index + 1]).compare(0, 2, "--") == 0) {
        throw std::invalid_argument(option + " requires " + description);
    }
    return argv[++index];
}

long double parse_speed(const std::string& value) {
    // Accept decimal/exponent notation only, with no skipped whitespace,
    // hexadecimal floats, named NaNs, or partially parsed suffixes.
    std::size_t i = value.front() == '+' ? 1 : 0;
    std::size_t digits = 0;
    while (i < value.size() && value[i] >= '0' && value[i] <= '9') {
        ++i;
        ++digits;
    }
    if (i < value.size() && value[i] == '.') {
        ++i;
        while (i < value.size() && value[i] >= '0' && value[i] <= '9') {
            ++i;
            ++digits;
        }
    }
    bool valid = digits != 0;
    if (i < value.size() && (value[i] == 'e' || value[i] == 'E')) {
        ++i;
        if (i < value.size() && (value[i] == '+' || value[i] == '-')) ++i;
        const auto exponent_start = i;
        while (i < value.size() && value[i] >= '0' && value[i] <= '9') ++i;
        valid = valid && i != exponent_start;
    }
    long double parsed = 0;
    std::istringstream input(value);
    input.imbue(std::locale::classic());
    input >> std::noskipws >> parsed;
    if (!valid || i != value.size() || !input || !input.eof() ||
        !std::isfinite(parsed) || parsed <= 0) {
        throw std::invalid_argument("--speed requires a finite positive decimal number: " + value);
    }
    return parsed;
}


uint64_t parse_u64(const std::string& value, const std::string& option, bool positive = true) {
    const char* first = value.data();
    const char* last = first + value.size();
    if (first != last && *first == '+') ++first;
    uint64_t parsed = 0;
    const auto result = std::from_chars(first, last, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != last || (positive && parsed == 0)) {
        throw std::invalid_argument(option + " requires a " +
            (positive ? "positive" : "non-negative") + " uint64 integer: " + value);
    }
    return parsed;
}

Options parse_options(int argc, char** argv) {
    if (argc < 2) throw std::invalid_argument("required: MODE and its options");
    Options options;
    options.mode = argv[1];
    if (!supported_mode(options.mode)) {
        throw std::invalid_argument("unsupported replay mode: " + options.mode);
    }
    std::set<std::string> required{"--if"};
    std::set<std::string> allowed;
    if (options.mode == "normal") {
        required.insert("--in");
        allowed = {"--if", "--in", "--speed", "--loop"};
    } else if (options.mode == "flood") {
        required.insert({"--id", "--data", "--interval-us", "--count"});
        allowed = required;
    } else if (options.mode == "replay") {
        required.insert({"--in", "--start-line", "--end-line", "--delay-ms", "--repeat"});
        allowed = required;
    } else {
        required.insert({"--id", "--base-data", "--period-us", "--count", "--flip-mask"});
        allowed = required;
    }
    std::set<std::string> seen;
    for (int i = 2; i < argc; ++i) {
        const std::string argument = argv[i];
        if (allowed.count(argument) == 0) {
            throw std::invalid_argument("unsupported option for " + options.mode + ": " + argument);
        }
        if (!seen.insert(argument).second) throw std::invalid_argument("duplicate " + argument + " option");
        if (argument == "--if") {
            options.interface_name = value_argument(i, argc, argv, "an interface name");
        } else if (argument == "--in") {
            options.input_path = value_argument(i, argc, argv, "a file path");
        } else if (argument == "--id") {
            options.id = value_argument(i, argc, argv, "a hexadecimal CAN ID");
        } else if (argument == "--data" || argument == "--base-data") {
            options.data = value_argument(i, argc, argv, "a hexadecimal payload", true);
        } else if (argument == "--flip-mask") {
            options.flip_mask = value_argument(i, argc, argv, "a hexadecimal 00/FF mask", true);
        } else if (argument == "--speed") {
            options.speed = parse_speed(value_argument(i, argc, argv, "a finite positive decimal number"));
        } else {
            const bool positive = argument != "--delay-ms";
            const auto value = parse_u64(value_argument(i, argc, argv,
                positive ? "a positive uint64 integer" : "a non-negative uint64 integer"), argument, positive);
            if (argument == "--loop") options.loop_count = value;
            else if (argument == "--interval-us" || argument == "--period-us") options.interval_us = value;
            else if (argument == "--count") options.count = value;
            else if (argument == "--start-line") options.start_line = value;
            else if (argument == "--end-line") options.end_line = value;
            else if (argument == "--delay-ms") options.delay_ms = value;
            else if (argument == "--repeat") options.repeat = value;
        }
    }
    for (const auto& option : required) {
        if (seen.count(option) == 0) throw std::invalid_argument("required: " + option + " for " + options.mode);
    }
    return options;
}

cansec::CanFrameRecord parse_cli_frame(std::string id, const std::string& payload) {
    if (id.compare(0, 2, "0x") == 0 || id.compare(0, 2, "0X") == 0) id.erase(0, 2);
    // CLI values are hex tokens, unlike a log line which permits whitespace.
    const auto hexadecimal = [](const std::string& value) {
        return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                   (ch >= 'A' && ch <= 'F');
        });
    };
    if (id.empty() || id.size() > 8 || !hexadecimal(id)) {
        throw std::invalid_argument("--id requires 1 to 8 hexadecimal digits after optional 0x");
    }
    if (!hexadecimal(payload)) {
        throw std::invalid_argument("payload/mask must contain only hexadecimal digits");
    }
    // Reuse the canonical parser for typed-ID ranges, byte pairs and DLC.
    const auto frame = cansec::parse_can_record_line("(0.000000) cli " + id + "#" + payload);
    if (!frame) throw std::invalid_argument("invalid CAN frame arguments");
    return *frame;
}

cansec::ReplayPlan make_plan(const Options& options) {
    if (options.mode == "normal") {
        cansec::ReplayPlan plan;
        plan.records = cansec::read_can_log_file(options.input_path);
        plan.schedule = cansec::make_replay_schedule(plan.records, options.speed, options.loop_count);
        return plan;
    }
    if (options.mode == "replay") {
        return cansec::make_segment_replay_plan(options.input_path, options.start_line,
            options.end_line, options.delay_ms, options.repeat);
    }
    const auto frame = parse_cli_frame(options.id, options.data);
    if (options.mode == "flood") {
        return cansec::make_flood_plan(frame, options.interval_us, options.count);
    }
    const auto mask_frame = parse_cli_frame("000", options.flip_mask);
    const std::vector<uint8_t> mask(mask_frame.data.begin(), mask_frame.data.begin() + mask_frame.dlc);
    return cansec::make_fuzz_plan(frame, mask, options.interval_us, options.count);
}

#if defined(__linux__)
volatile std::sig_atomic_t stop_requested = 0;

void request_stop(int) { stop_requested = 1; }

class SocketHandle {
public:
    explicit SocketHandle(int fd) : fd_(fd) {}
    ~SocketHandle() { cansec::close_socket(fd_); }
    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

class SignalHandlers {
public:
    SignalHandlers() {
        stop_requested = 0;
        struct sigaction action{};
        action.sa_handler = request_stop;
        sigemptyset(&action.sa_mask);
        // No SA_RESTART: signals also interrupt a pending CAN write.
        if (sigaction(SIGINT, &action, &previous_int_) != 0) {
            throw std::system_error(errno, std::generic_category(), "failed to install SIGINT handler");
        }
        if (sigaction(SIGTERM, &action, &previous_term_) != 0) {
            const int error = errno;
            sigaction(SIGINT, &previous_int_, nullptr);
            throw std::system_error(error, std::generic_category(), "failed to install SIGTERM handler");
        }
    }
    ~SignalHandlers() {
        sigaction(SIGINT, &previous_int_, nullptr);
        sigaction(SIGTERM, &previous_term_, nullptr);
    }
    SignalHandlers(const SignalHandlers&) = delete;
    SignalHandlers& operator=(const SignalHandlers&) = delete;
private:
    struct sigaction previous_int_{};
    struct sigaction previous_term_{};
};

timespec monotonic_now() {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        throw std::system_error(errno, std::generic_category(), "clock_gettime(CLOCK_MONOTONIC) failed");
    }
    return now;
}

timespec target_time(const timespec& origin, uint64_t offset_us) {
    if (origin.tv_sec < 0 || origin.tv_nsec < 0 || origin.tv_nsec >= 1000000000L) {
        throw std::runtime_error("invalid CLOCK_MONOTONIC time");
    }
    const auto maximum_seconds = static_cast<uint64_t>(std::numeric_limits<time_t>::max());
    const auto start_seconds = static_cast<uint64_t>(origin.tv_sec);
    const uint64_t nanoseconds = static_cast<uint64_t>(origin.tv_nsec) + (offset_us % 1000000ULL) * 1000ULL;
    const uint64_t seconds = offset_us / 1000000ULL + nanoseconds / 1000000000ULL;
    if (seconds > maximum_seconds - start_seconds) {
        throw std::overflow_error("replay CLOCK_MONOTONIC target exceeds time_t range");
    }
    timespec result{};
    result.tv_sec = static_cast<time_t>(start_seconds + seconds);
    result.tv_nsec = static_cast<long>(nanoseconds % 1000000000ULL);
    return result;
}

bool wait_until(const timespec& target) {
    while (!stop_requested) {
        const auto now = monotonic_now();
        if (now.tv_sec > target.tv_sec ||
            (now.tv_sec == target.tv_sec && now.tv_nsec >= target.tv_nsec)) {
            return !stop_requested;
        }
        const auto remaining_seconds = target.tv_sec - now.tv_sec;
        const bool over_slice = remaining_seconds > 1 ||
            (remaining_seconds == 1 && 1000000000L + target.tv_nsec - now.tv_nsec > 100000000L) ||
            (remaining_seconds == 0 && target.tv_nsec - now.tv_nsec > 100000000L);
        // Keep the frame's original absolute deadline. Bounded intermediate
        // waits close the signal/check/sleep race without accumulating drift.
        const auto wake = over_slice ? target_time(now, 100000) : target;
        if (stop_requested) return false;
        const int result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &wake, nullptr);
        if (stop_requested) return false;
        if (result != 0 && result != EINTR) {
            throw std::system_error(result, std::generic_category(), "clock_nanosleep() failed");
        }
    }
    return false;
}

bool send_record(int fd, const cansec::CanFrameRecord& record) {
    while (!stop_requested) {
        try {
            cansec::write_can_frame(fd, record);
            return true;
        } catch (const std::system_error& error) {
            if (error.code().value() != EINTR) throw;
        }
    }
    return false;
}
#endif

void transmit_plan(const Options& options, const cansec::ReplayPlan& plan) {
#if defined(__linux__)
    const auto& schedule = plan.schedule;
    const auto& records = plan.records;
    if (plan.initial_delay_us > std::numeric_limits<uint64_t>::max() - schedule.total_duration_us) {
        throw std::overflow_error("replay delay plus duration exceeds uint64 microsecond range");
    }
    const auto final_offset = plan.initial_delay_us + schedule.total_duration_us;
    // All data and the final absolute clock target are checked before sending.
    (void)target_time(monotonic_now(), final_offset);
    const SocketHandle socket(cansec::open_can_socket(options.interface_name));
    const SignalHandlers signals;
    const auto origin = monotonic_now();
    (void)target_time(origin, final_offset);
    std::cerr << "Replaying " << options.mode << " CAN frames to " << options.interface_name << '\n';
    uint64_t sent = 0;
    for (uint64_t loop = 0; loop < schedule.loop_count && !stop_requested; ++loop) {
        const uint64_t loop_start_us = plan.initial_delay_us + loop * schedule.loop_duration_us;
        for (std::size_t i = 0; i < records.size(); ++i) {
            const auto target = target_time(origin, loop_start_us + schedule.offsets_us[i]);
            if (!wait_until(target) || stop_requested) break;
            if (!send_record(socket.get(), records[i])) break;
            ++sent;
        }
    }
    std::cerr << "Sent " << sent << " frame(s).\n";
    if (stop_requested) std::cerr << "Interrupted by signal.\n";
#else
    (void)plan;
    throw std::runtime_error(options.mode == "normal" ? "Normal replay requires Linux" : "Replay requires Linux");
#endif
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if ((argc == 2 && std::string(argv[1]) == "--help") ||
            (argc == 3 && supported_mode(argv[1]) && std::string(argv[2]) == "--help")) {
            print_usage();
            return 0;
        }
        const auto options = parse_options(argc, argv);
        const auto plan = make_plan(options);
        transmit_plan(options, plan);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "cansec-replay: " << error.what() << '\n';
        return 1;
    }
}
