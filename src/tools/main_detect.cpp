#include "cansec/baseline.hpp"
#include "cansec/detector.hpp"
#include "cansec/logio.hpp"
#include "cansec/alert_json.hpp"
#include "cansec/report.hpp"
#include "cansec/sha256.hpp"
#include "cansec/build_info.hpp"

#if defined(__linux__)
#include "cansec/socketcan.hpp"
#include <cerrno>
#include <csignal>
#include <sys/utsname.h>
#endif

#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <memory>
#include <limits>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

struct Options {
    std::string rules_path;
    std::string log_path;
    std::string interface_name;
    std::string output_path;
    std::string summary_path;
    std::string rules_sha256;
    std::string command_line;
    bool validate_rules = false;
    int max_frames = 0;
    int max_seconds = 0;
};

void flush_stdout() {
    std::cout.flush();
    if (!std::cout) {
        throw std::runtime_error("failed to write standard output");
    }
}

void print_usage() {
    std::cout << "Usage: cansec-detect --rules FILE --validate-rules\n"
                 "       cansec-detect --rules FILE --check-log LOG [--summary FILE]\n"
                 "       cansec-detect --rules FILE --if IFACE --out FILE [--max-frames N] [--max-seconds S] [--summary FILE]\n"
                 "\n"
                 "  --validate-rules    check the baseline file and exit\n"
                 "  --check-log LOG     check a saved log; alerts are printed to stdout\n"
                 "  --if IFACE --out F  live detection on a SocketCAN interface; alerts are written as JSONL\n"
                 "  --summary FILE      also write a Markdown report\n"
                 "  --max-frames N      stop after N frames (0 = no limit)\n"
                 "  --max-seconds S     stop after S seconds (0 = no limit)\n"
                 "\n"
                 "Exit code 0 means the check ran, not that no rule fired.\n"
                 "Live detection requires Linux.\n";
}

std::string value_argument(int& index, int argc, char** argv, const std::string& description) {
    const std::string option = argv[index];
    if (index + 1 >= argc || std::string(argv[index + 1]).empty() ||
        std::string(argv[index + 1]).compare(0, 2, "--") == 0) {
        throw std::runtime_error(option + " requires " + description);
    }
    return argv[++index];
}

int limit_argument(int& index, int argc, char** argv) {
    const std::string option = argv[index];
    const auto value = value_argument(index, argc, argv, "a nonnegative integer");
    const char* first = value.data();
    const char* last = first + value.size();
    if (first != last && *first == '+') {
        ++first;
        if (first == last || *first < '0' || *first > '9') {
            throw std::runtime_error(option + " requires a nonnegative integer: " + value);
        }
    }
    int parsed = 0;
    const auto result = std::from_chars(first, last, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != last || parsed < 0) {
        throw std::runtime_error(option + " requires a nonnegative integer: " + value);
    }
    return parsed;
}

Options parse_options(int argc, char** argv) {
    Options options;
    std::set<std::string> seen;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument != "--rules" && argument != "--check-log" && argument != "--validate-rules" &&
            argument != "--if" && argument != "--out" && argument != "--summary" && argument != "--max-frames" && argument != "--max-seconds") {
            throw std::runtime_error("unsupported option: " + argument);
        }
        if (!seen.insert(argument).second) {
            throw std::runtime_error("duplicate " + argument + " option");
        }
        if (argument == "--rules") options.rules_path = value_argument(i, argc, argv, "a file path");
        else if (argument == "--check-log") options.log_path = value_argument(i, argc, argv, "a file path");
        else if (argument == "--validate-rules") options.validate_rules = true;
        else if (argument == "--if") options.interface_name = value_argument(i, argc, argv, "an interface name");
        else if (argument == "--out") options.output_path = value_argument(i, argc, argv, "a file path");
        else if (argument == "--summary") options.summary_path = value_argument(i, argc, argv, "a file path");
        else if (argument == "--max-frames") options.max_frames = limit_argument(i, argc, argv);
        else if (argument == "--max-seconds") options.max_seconds = limit_argument(i, argc, argv);
    }
    if (options.validate_rules && !options.log_path.empty()) {
        throw std::runtime_error("choose either --validate-rules or --check-log");
    }
    if (options.validate_rules && !options.summary_path.empty()) {
        throw std::runtime_error("--summary cannot be combined with --validate-rules");
    }
    const bool offline = options.validate_rules || !options.log_path.empty();
    const bool live_option = seen.count("--if") || seen.count("--out") ||
                             seen.count("--max-frames") || seen.count("--max-seconds");
    if (offline && live_option) {
        throw std::runtime_error("live options cannot be combined with --validate-rules or --check-log");
    }
    if (options.rules_path.empty() || (!offline && (options.interface_name.empty() || options.output_path.empty()))) {
        throw std::runtime_error("required: --rules FILE and --validate-rules, --check-log LOG, or --if IFACE --out FILE");
    }
    return options;
}

bool same_file(const std::string& lhs, const std::string& rhs) {
    namespace fs = std::filesystem;
    if (fs::exists(lhs) && fs::exists(rhs) && fs::equivalent(lhs, rhs)) return true;
    const auto left = fs::weakly_canonical(fs::absolute(lhs));
    const auto right = fs::weakly_canonical(fs::absolute(rhs));
#if defined(_WIN32)
    return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL;
#else
    return left == right;
#endif
}

void prevent_rules_output_alias(const Options& options) {
    if (same_file(options.rules_path, options.output_path)) {
        throw std::runtime_error("--out must not alias the --rules input file");
    }
}

void validate_summary_path(const Options& options) {
    if (options.summary_path.empty()) return;
    namespace fs = std::filesystem;
    for (const auto& other : {options.rules_path, options.log_path, options.output_path}) {
        if (!other.empty() && same_file(options.summary_path, other)) {
            throw std::runtime_error("--summary must not alias an input or --out file");
        }
    }
    if (!options.output_path.empty() && fs::exists(options.output_path) &&
        !fs::is_regular_file(options.output_path)) {
        throw std::runtime_error("--summary requires a regular JSONL output file");
    }
    const fs::path path(options.summary_path);
#if defined(_WIN32)
    for (const auto& part : path) {
        const auto& name = part.native();
        if (name != L"." && name != L".." && !name.empty() &&
            (name.back() == L'.' || name.back() == L' ')) {
            throw std::runtime_error("summary path component must not end with a dot or space");
        }
    }
#endif
    if (fs::exists(path) && !fs::is_regular_file(path)) {
        throw std::runtime_error("summary output is not a regular file: " + options.summary_path);
    }
    if (!fs::is_directory(fs::absolute(path).parent_path())) {
        throw std::runtime_error("summary output parent must exist: " + options.summary_path);
    }
}

// The private staging directory is prepared before live JSONL is truncated.
// Only this report is published here; JSONL remains an incremental live record.
class ReportOutput {
public:
    explicit ReportOutput(const std::string& destination) : destination_(destination) {
        const auto parent = std::filesystem::absolute(destination_).parent_path();
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        for (int i = 0; i < 100; ++i) {
            directory_ = parent / (".cansec-report-" + std::to_string(stamp) + "-" + std::to_string(i));
            if (std::filesystem::create_directory(directory_)) {
                staged_ = directory_ / "new";
                backup_ = directory_ / "previous";
                std::ofstream probe(staged_, std::ios::binary);
                probe.close();
                if (!probe) {
                    std::error_code ignored;
                    std::filesystem::remove(staged_, ignored);
                    std::filesystem::remove(directory_, ignored);
                    throw std::runtime_error("failed to prepare summary output: " + destination);
                }
                return;
            }
        }
        throw std::runtime_error("failed to prepare summary staging directory: " + destination);
    }
    ReportOutput(const ReportOutput&) = delete;
    ReportOutput& operator=(const ReportOutput&) = delete;
    ~ReportOutput() {
        if (has_backup_) return;  // rollback failed: keep the backup
        std::error_code ignored;
        std::filesystem::remove(staged_, ignored);
        std::filesystem::remove(backup_, ignored);
        std::filesystem::remove(directory_, ignored);
    }
    void write(const std::string& content) {
        std::ofstream output(staged_, std::ios::binary | std::ios::trunc);
        output << content;
        output.close();
        if (!output) throw std::runtime_error("failed to write summary output: " + destination_.string());
    }
    void publish() {
        namespace fs = std::filesystem;
        try {
            if (fs::exists(destination_)) {
                if (!fs::is_regular_file(destination_)) {
                    throw std::runtime_error("summary output is not a regular file: " + destination_.string());
                }
                fs::rename(destination_, backup_);
                has_backup_ = true;
            }
            fs::rename(staged_, destination_);
        } catch (...) {
            if (has_backup_) {
                std::error_code error;
                fs::rename(backup_, destination_, error);
                if (error) {
                    std::cerr << "Could not restore summary; previous report retained at " << backup_ << '\n';
                } else {
                    has_backup_ = false;
                }
            }
            throw;
        }
        has_backup_ = false;
    }
private:
    std::filesystem::path destination_, directory_, staged_, backup_;
    bool has_backup_ = false;
};

std::string utc_now() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::system_clock::to_time_t(now);
    const auto* value = std::gmtime(&seconds);
    if (!value) throw std::runtime_error("failed to format UTC run time");
    std::ostringstream result;
    result << std::put_time(value, "%Y-%m-%dT%H:%M:%SZ");
    return result.str();
}

// The Windows CRT supplies narrow argv in the active Windows code page.
// Keep those native bytes for existing filesystem APIs, but render UTF-8 text.
std::string metadata_text(const std::string& native) {
#if defined(_WIN32)
    if (native.empty()) return {};
    if (native.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("metadata argument is too long");
    }
    const auto length = static_cast<int>(native.size());
    const int wide_length = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS,
        native.data(), length, nullptr, 0);
    if (wide_length == 0) throw std::runtime_error("failed to decode native Windows argument");
    std::wstring wide(static_cast<std::size_t>(wide_length), L'\0');
    if (MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, native.data(), length,
            wide.data(), wide_length) != wide_length) {
        throw std::runtime_error("failed to decode native Windows argument");
    }
    const int utf8_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        wide.data(), wide_length, nullptr, 0, nullptr, nullptr);
    if (utf8_length == 0) throw std::runtime_error("failed to encode metadata as UTF-8");
    std::string utf8(static_cast<std::size_t>(utf8_length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.data(), wide_length,
            utf8.data(), utf8_length, nullptr, nullptr) != utf8_length) {
        throw std::runtime_error("failed to encode metadata as UTF-8");
    }
    return utf8;
#else
    return native;
#endif
}

cansec::ReportMetadata report_metadata(const Options& options) {
    cansec::ReportMetadata result;
    result.started_utc = utc_now();
    result.mode = options.log_path.empty() ? "live" : "offline";
    result.git_commit = cansec::build_info::git_commit;
    result.source_sha256 = cansec::build_info::source_sha256;
    result.build_type = cansec::build_info::build_type;
    if (result.build_type.empty()) result.build_type = "unspecified";
    result.compiler = cansec::build_info::compiler;
    result.os = cansec::build_info::os;
    result.kernel = "unavailable";
#if defined(__linux__)
    utsname info{};
    if (uname(&info) == 0) result.kernel = info.release;
#endif
    result.interface_name = options.interface_name.empty() ? "from input log" : options.interface_name;
    result.rules_path = metadata_text(options.rules_path);
    result.rules_sha256 = options.rules_sha256;
    result.input_path = metadata_text(options.log_path);
    result.alerts_path = metadata_text(options.output_path);
    result.command_line = options.command_line;
    result.max_frames = static_cast<uint64_t>(options.max_frames);
    result.max_seconds = static_cast<uint64_t>(options.max_seconds);
    return result;
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
        // No SA_RESTART: a termination signal can interrupt the blocking read.
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
#endif

void detect_live(const cansec::DetectionBaseline& baseline, const Options& options) {
    prevent_rules_output_alias(options);
#if defined(__linux__)
    cansec::Detector detector(baseline);
    const SocketHandle socket(cansec::open_can_socket(options.interface_name));
    cansec::set_socket_read_timeout_ms(socket.get(), 100);
    const SignalHandlers signals;
    std::unique_ptr<ReportOutput> summary;
    cansec::DetectionReport report;
    cansec::ReportMetadata metadata;
    if (!options.summary_path.empty()) {
        summary = std::make_unique<ReportOutput>(options.summary_path);
        metadata = report_metadata(options);
    }
    std::ofstream output(options.output_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to open output file: " + options.output_path);
    }
    // On case-insensitive mounted filesystems, two previously absent names can
    // become aliases once JSONL exists. Recheck before receiving or publishing.
    validate_summary_path(options);
    const auto start = std::chrono::steady_clock::now();
    uint64_t processed = 0;
    uint64_t alert_count = 0;
    std::cerr << "Detecting CAN frames from " << options.interface_name << " -> " << options.output_path << '\n';
    std::string termination = "signal";
    while (!stop_requested) {
        if (options.max_frames > 0 && processed >= static_cast<uint64_t>(options.max_frames)) {
            termination = "max_frames";
            break;
        }
        if (options.max_seconds > 0 && std::chrono::steady_clock::now() - start >= std::chrono::seconds(options.max_seconds)) {
            termination = "max_seconds";
            break;
        }
        std::optional<cansec::CanFrameRecord> record;
        try {
            record = cansec::read_can_frame(socket.get(), options.interface_name);
        } catch (const std::system_error& error) {
            if (error.code().value() == EINTR) {
                if (stop_requested) break;
                continue;
            }
            throw;
        }
        if (!record) continue;
        auto alerts = detector.process(*record, 0);
        // Capture time comes from SocketCAN; decision time is sampled after all
        // detector rules have processed this frame, using the same wall clock.
        const auto alert_time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        for (auto& alert : alerts) {
            alert.alert_ts_us = static_cast<uint64_t>(alert_time);
            output << cansec::format_alert_json(alert) << '\n';
            if (!output) throw std::runtime_error("failed to write output file: " + options.output_path);
            ++alert_count;
        }
        output.flush();
        if (!output) throw std::runtime_error("failed to flush output file: " + options.output_path);
        if (summary) report.observe(*record, alerts);
        ++processed;
    }
    output.close();
    if (!output) throw std::runtime_error("failed to close output file: " + options.output_path);
    if (summary) {
        metadata.finished_utc = utc_now();
        metadata.termination_reason = termination;
        metadata.elapsed_us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count());
        metadata.alerts_sha256 = cansec::sha256_file(options.output_path);
        summary->write(cansec::format_detection_report(metadata, report));
        validate_summary_path(options);
        summary->publish();
    }
    std::cerr << "Processed " << processed << " frame(s); " << alert_count << " alert(s).\n";
#else
    (void)baseline;
    throw std::runtime_error("Live detection requires Linux");
#endif
}

const char* rule_name(cansec::AlertRule rule) {
    switch (rule) {
        case cansec::AlertRule::UnknownId: return "UNKNOWN_ID";
        case cansec::AlertRule::DlcMismatch: return "DLC_MISMATCH";
        case cansec::AlertRule::PeriodViolation: return "PERIOD_VIOLATION";
        case cansec::AlertRule::RateSpike: return "RATE_SPIKE";
        case cansec::AlertRule::FixedByteViolation: return "FIXED_BYTE_VIOLATION";
        case cansec::AlertRule::ReplayBurst: return "REPLAY_BURST";
        default: throw std::logic_error("unsupported rule in offline detector output");
    }
}

const char* severity_name(cansec::Severity severity) {
    switch (severity) {
        case cansec::Severity::Low: return "LOW";
        case cansec::Severity::Medium: return "MEDIUM";
        case cansec::Severity::High: return "HIGH";
    }
    throw std::logic_error("unsupported alert severity");
}

void check_log(const cansec::DetectionBaseline& baseline, const Options& options) {
    const auto& path = options.log_path;
    const bool summarize = !options.summary_path.empty();
    cansec::ReportMetadata metadata;
    cansec::DetectionReport summary;
    if (summarize) {
        metadata = report_metadata(options);
        metadata.input_sha256 = cansec::sha256_file(path);
    }
    const auto start = std::chrono::steady_clock::now();
    // Parse the whole file first so a bad line near the end can't produce a
    // report that looks like a complete check.
    const auto records = cansec::read_can_log_file(path);
    if (summarize && metadata.input_sha256 != cansec::sha256_file(path)) {
        throw std::runtime_error("input log changed while reading; use a stable input file");
    }
    if (records.empty()) {
        throw std::runtime_error("no CAN frames in log: " + path);
    }
    cansec::Detector detector(baseline);
    // Also hold output until every record validates (e.g. timestamp order).
    std::ostringstream report;
    std::size_t count = 0;
    for (const auto& record : records) {
        const auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto alerts = detector.process(record, static_cast<uint64_t>(now_us));
        if (summarize) summary.observe(record, alerts);
        for (const auto& alert : alerts) {
            report << rule_name(alert.rule) << ' ' << severity_name(alert.severity)
                   << ' ' << cansec::format_can_record(record)
                   << " " << alert.detail << '\n';
            ++count;
        }
    }
    report << "Checked " << records.size()
           << " frames using UNKNOWN_ID,DLC_MISMATCH,PERIOD_VIOLATION,RATE_SPIKE,FIXED_BYTE_VIOLATION,REPLAY_BURST only; "
           << count << " alerts.\n";
    if (!report) {
        throw std::runtime_error("failed to prepare offline report");
    }
    std::unique_ptr<ReportOutput> staged;
    if (summarize) {
        metadata.finished_utc = utc_now();
        metadata.termination_reason = "end_of_log";
        metadata.elapsed_us = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count());
        staged = std::make_unique<ReportOutput>(options.summary_path);
        staged->write(cansec::format_detection_report(metadata, summary));
    }
    std::cout << report.str();
    flush_stdout();
    if (staged) {
        validate_summary_path(options);
        staged->publish();
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--help") {
            print_usage();
            flush_stdout();
            return 0;
        }
        auto options = parse_options(argc, argv);
        validate_summary_path(options);
        if (!options.summary_path.empty()) {
            options.rules_sha256 = cansec::sha256_file(options.rules_path);
            std::ostringstream invocation;
            for (int i = 0; i < argc; ++i) {
                if (i) invocation << ' ';
                invocation << std::quoted(metadata_text(argv[i]));
            }
            options.command_line = invocation.str();
        }
        const auto baseline = cansec::load_baseline_ini(options.rules_path);
        if (!options.summary_path.empty() && options.rules_sha256 != cansec::sha256_file(options.rules_path)) {
            throw std::runtime_error("rules file changed while loading; use a stable input file");
        }
        if (options.validate_rules) {
            std::cout << "Baseline valid: " << baseline.entries.size()
                      << " IDs, window_ms=" << baseline.window_ms << '\n';
        } else if (!options.log_path.empty()) {
            check_log(baseline, options);
        } else {
            detect_live(baseline, options);
        }
        flush_stdout();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "cansec-detect: " << error.what() << '\n';
        return 1;
    }
}
