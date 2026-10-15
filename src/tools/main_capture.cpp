#include "cansec/logio.hpp"
#include "cansec/socketcan.hpp"

#include <charconv>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>

namespace {

struct CaptureOptions {
    std::string interface_name;
    std::string output_path;
    int max_frames = 0;
    int max_seconds = 0;
    bool recv_own_msgs = false;
};

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

void print_usage() {
    std::cerr
        << "Usage:\n"
        << "  cansec-capture --if vcan0 --out captures/benign.log [--max-frames N] [--max-seconds S] [--recv-own]\n\n"
        << "Examples:\n"
        << "  ./build/cansec-capture --if vcan0 --out captures/benign.log --max-frames 10\n"
        << "  ./build/cansec-capture --if vcan0 --out captures/benign.log --max-seconds 30\n";
}

int parse_int(const std::string& value, const std::string& name) {
    const char* first = value.data();
    const char* last = first + value.size();
    // from_chars accepts a minus sign but not a plus sign; retain valid +N input.
    if (first != last && *first == '+') {
        ++first;
        if (first == last || *first < '0' || *first > '9') {
            throw std::runtime_error("invalid integer for " + name + ": " + value);
        }
    }
    int parsed = 0;
    const auto result = std::from_chars(first, last, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != last) {
        throw std::runtime_error("invalid integer for " + name + ": " + value);
    }
    return parsed;
}

CaptureOptions parse_args(int argc, char** argv) {
    CaptureOptions options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--if" && i + 1 < argc) {
            options.interface_name = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            options.output_path = argv[++i];
        } else if (arg == "--max-frames" && i + 1 < argc) {
            options.max_frames = parse_int(argv[++i], "--max-frames");
        } else if (arg == "--max-seconds" && i + 1 < argc) {
            options.max_seconds = parse_int(argv[++i], "--max-seconds");
        } else if (arg == "--recv-own") {
            options.recv_own_msgs = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            std::exit(0);
        } else {
            throw std::runtime_error("unknown or incomplete argument: " + arg);
        }
    }

    if (options.interface_name.empty()) {
        throw std::runtime_error("missing required option: --if");
    }

    if (options.output_path.empty()) {
        throw std::runtime_error("missing required option: --out");
    }

    if (options.max_frames < 0 || options.max_seconds < 0) {
        throw std::runtime_error("--max-frames and --max-seconds must be non-negative");
    }

    return options;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const CaptureOptions options = parse_args(argc, argv);

        const SocketHandle socket(cansec::open_can_socket(options.interface_name, options.recv_own_msgs));

        // Allows --max-seconds to stop even when no frame arrives.
        cansec::set_socket_read_timeout_ms(socket.get(), 100);

        // Do not truncate an existing log until interface setup has succeeded.
        std::ofstream output(options.output_path);
        if (!output) {
            throw std::runtime_error("failed to open output file: " + options.output_path);
        }

        const auto start_time = std::chrono::steady_clock::now();
        int captured = 0;

        std::cerr << "Capturing CAN frames from " << options.interface_name
                  << " -> " << options.output_path << "\n";

        while (true) {
            if (options.max_frames > 0 && captured >= options.max_frames) {
                break;
            }

            if (options.max_seconds > 0) {
                const auto now = std::chrono::steady_clock::now();
                const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
                if (elapsed >= options.max_seconds) {
                    break;
                }
            }

            std::optional<cansec::CanFrameRecord> record;
            try {
                record = cansec::read_can_frame(socket.get(), options.interface_name);
            } catch (const std::system_error& error) {
                // A signal can interrupt a timed receive without invalidating
                // the socket. Recheck the outer loop's limits before retrying.
                if (error.code().value() == EINTR) continue;
                throw;
            }
            if (!record.has_value()) {
                continue;
            }

            cansec::write_can_record(output, record.value());
            if (!output) {
                throw std::runtime_error("failed to write output file: " + options.output_path);
            }
            output.flush();
            if (!output) {
                throw std::runtime_error("failed to flush output file: " + options.output_path);
            }

            ++captured;
        }

        output.close();
        if (!output) {
            throw std::runtime_error("failed to close output file: " + options.output_path);
        }

        std::cerr << "Captured " << captured << " frame(s).\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "cansec-capture error: " << e.what() << "\n";
        print_usage();
        return 1;
    }
}
