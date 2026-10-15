#include "cansec/logio.hpp"
#include "cansec/profile.hpp"
#include "cansec/sha256.hpp"

#include <cstdlib>
#include <chrono>
#include <exception>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

struct ProfileOptions {
    std::string input_path;
    std::string output_path;
    std::string summary_path;
    std::string override_path;
};

void print_usage(std::ostream& out) {
    out << "Usage:\n"
        << "  cansec-profile --in benign.log --out baseline.ini\n"
        << "                 --summary profile_summary.md [--override overrides.ini]\n\n"
        << "Build a baseline from a Classical CAN log. No CAN interface is needed.\n";
}

ProfileOptions parse_args(int argc, char** argv) {
    ProfileOptions options;
    std::set<std::string> seen;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(std::cout);
            std::exit(0);
        }
        if (arg != "--in" && arg != "--out" && arg != "--summary" && arg != "--override") {
            throw std::runtime_error("unknown argument: " + arg);
        }
        if (!seen.insert(arg).second) {
            throw std::runtime_error("duplicate option: " + arg);
        }
        if (i + 1 >= argc || std::string(argv[i + 1]).empty() ||
            std::string(argv[i + 1]).rfind("--", 0) == 0) {
            throw std::runtime_error("missing value for " + arg);
        }
        const std::string value = argv[++i];
        if (arg == "--in") options.input_path = value;
        else if (arg == "--out") options.output_path = value;
        else if (arg == "--summary") options.summary_path = value;
        else options.override_path = value;
    }
    if (options.input_path.empty()) throw std::runtime_error("missing required option: --in");
    if (options.output_path.empty()) throw std::runtime_error("missing required option: --out");
    if (options.summary_path.empty()) throw std::runtime_error("missing required option: --summary");
    return options;
}

bool same_file(const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
    if (std::filesystem::exists(lhs) && std::filesystem::exists(rhs) &&
        std::filesystem::equivalent(lhs, rhs)) {
        return true;
    }
    // Nonexistent relative names may stay relative in weakly_canonical on Linux.
    // Use one absolute basis before comparing aliases such as file and ./file.
    const auto left = std::filesystem::weakly_canonical(std::filesystem::absolute(lhs));
    const auto right = std::filesystem::weakly_canonical(std::filesystem::absolute(rhs));
#if defined(_WIN32)
    // Nonexistent output names still alias on a case-insensitive filesystem.
    return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL;
#else
    return left == right;
#endif
}

void validate_output_paths(const ProfileOptions& options) {
    for (const auto& path : {options.output_path, options.summary_path}) {
#if defined(_WIN32)
        for (const auto& component : std::filesystem::path(path)) {
            const auto& name = component.native();
            if (name != L"." && name != L".." && !name.empty() &&
                (name.back() == L'.' || name.back() == L' ')) {
                throw std::runtime_error("Windows output path must not end a component with a dot or space: " + path);
            }
        }
#endif
        if (same_file(path, options.input_path) ||
            (!options.override_path.empty() && same_file(path, options.override_path))) {
            throw std::runtime_error("output must not overwrite an input file: " + path);
        }
        if (std::filesystem::exists(path) && !std::filesystem::is_regular_file(path)) {
            throw std::runtime_error("output is not a regular file: " + path);
        }
    }
    if (same_file(options.output_path, options.summary_path)) {
        throw std::runtime_error("baseline and summary must use different output files");
    }
}

void create_parent(const std::string& path) {
    const auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent);
}

// Stage both files before replacing either result. Each backup stays on the
// destination filesystem so a failed second publish can restore the first.
class StagedOutput {
public:
    explicit StagedOutput(const std::string& path) : destination_(path) {
        const auto parent = std::filesystem::absolute(destination_).parent_path();
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        for (int attempt = 0; attempt < 100; ++attempt) {
            directory_ = parent / (".cansec-profile-" + std::to_string(stamp) + "-" + std::to_string(attempt));
            if (std::filesystem::create_directory(directory_)) {
                staged_ = directory_ / "new";
                backup_ = directory_ / "previous";
                return;
            }
        }
        throw std::runtime_error("cannot create staging directory for " + path);
    }

    StagedOutput(const StagedOutput&) = delete;
    StagedOutput& operator=(const StagedOutput&) = delete;

    ~StagedOutput() {
        if (has_backup_) return;  // rollback failed: keep the backup
        std::error_code error;
        std::filesystem::remove(staged_, error);
        std::filesystem::remove(backup_, error);
        std::filesystem::remove(directory_, error);
    }

    std::string path() const { return staged_.string(); }

    void publish() {
        if (std::filesystem::exists(destination_)) {
            if (!std::filesystem::is_regular_file(destination_)) {
                throw std::runtime_error("output is not a regular file: " + destination_.string());
            }
            std::filesystem::rename(destination_, backup_);
            has_backup_ = true;
        }
        std::filesystem::rename(staged_, destination_);
        published_ = true;
    }

    void accept() { has_backup_ = false; }

    void rollback() noexcept {
        std::error_code error;
        if (published_) {
            std::filesystem::remove(destination_, error);
            if (error) {
                std::cerr << "Could not restore output; retained backup at " << backup_ << "\n";
                return;
            }
            published_ = false;
        }
        if (has_backup_) {
            std::filesystem::rename(backup_, destination_, error);
            if (error) {
                std::cerr << "Could not restore output; retained backup at " << backup_ << "\n";
                return;
            }
            has_backup_ = false;
        }
    }

private:
    std::filesystem::path destination_, directory_, staged_, backup_;
    bool has_backup_ = false;
    bool published_ = false;
};

void write_outputs(const cansec::BaselineProfile& baseline, const ProfileOptions& options) {
    create_parent(options.output_path);
    create_parent(options.summary_path);
    validate_output_paths(options);
    StagedOutput ini(options.output_path);
    StagedOutput summary(options.summary_path);
    cansec::write_baseline_ini(baseline, ini.path());
    cansec::write_profile_summary(baseline, summary.path());
    try {
        ini.publish();
        // The actual filesystem can alias names that looked distinct before creation
        // (for example WSL writing case variants onto a Windows drive).
        if (same_file(options.output_path, options.summary_path)) {
            throw std::runtime_error("baseline and summary must use different output files");
        }
        summary.publish();
    } catch (...) {
        summary.rollback();
        ini.rollback();
        throw;
    }
    ini.accept();
    summary.accept();
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto options = parse_args(argc, argv);
        validate_output_paths(options);
        const auto initial_hash = cansec::sha256_file(options.input_path);
        const auto records = cansec::read_can_log_file(options.input_path);
        auto baseline = cansec::build_baseline_profile(records, options.input_path);
        if (baseline.benign_source_sha256 != initial_hash) {
            throw std::runtime_error("input log changed while profiling; retry with a stable input file");
        }
        if (!options.override_path.empty()) {
            cansec::apply_baseline_overrides(baseline, options.override_path);
        }
        write_outputs(baseline, options);
        std::cout << "Profiled " << records.size() << " frame(s), "
                  << baseline.entries.size() << " CAN ID(s).\n"
                  << "Input SHA-256: " << baseline.benign_source_sha256 << "\n"
                  << "Baseline: " << options.output_path << "\n"
                  << "Summary: " << options.summary_path << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "cansec-profile error: " << e.what() << "\n";
        print_usage(std::cerr);
        return 1;
    }
}
