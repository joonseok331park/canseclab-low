#include "cansec/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace cansec {
namespace {

constexpr std::array<uint32_t, 64> round_constants{{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
}};

uint32_t rotate_right(uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32U - bits));
}

class Sha256 {
public:
    void update(const uint8_t* data, std::size_t size) {
        if (size > std::numeric_limits<uint64_t>::max() / 8U - total_bytes_) {
            throw std::runtime_error("file exceeds SHA-256 bit-length capacity");
        }
        total_bytes_ += static_cast<uint64_t>(size);
        while (size != 0) {
            const auto copied = std::min(size, block_.size() - used_);
            std::copy_n(data, copied, block_.begin() + used_);
            used_ += copied;
            data += copied;
            size -= copied;
            if (used_ == block_.size()) {
                transform();
                used_ = 0;
            }
        }
    }

    std::string finish() {
        const uint64_t bit_length = total_bytes_ * 8U;
        block_[used_++] = 0x80U;
        if (used_ > 56) {
            std::fill(block_.begin() + used_, block_.end(), 0);
            transform();
            used_ = 0;
        }
        std::fill(block_.begin() + used_, block_.begin() + 56, 0);
        for (std::size_t i = 0; i < 8; ++i) {
            block_[63 - i] = static_cast<uint8_t>(bit_length >> (8U * i));
        }
        transform();

        std::ostringstream result;
        result << std::hex << std::setfill('0');
        for (const auto word : state_) {
            result << std::setw(8) << word;
        }
        return result.str();
    }

private:
    void transform() {
        std::array<uint32_t, 64> schedule{};
        for (std::size_t i = 0; i < 16; ++i) {
            const auto offset = i * 4;
            schedule[i] = (static_cast<uint32_t>(block_[offset]) << 24U) |
                          (static_cast<uint32_t>(block_[offset + 1]) << 16U) |
                          (static_cast<uint32_t>(block_[offset + 2]) << 8U) |
                          static_cast<uint32_t>(block_[offset + 3]);
        }
        for (std::size_t i = 16; i < schedule.size(); ++i) {
            const auto previous15 = schedule[i - 15];
            const auto previous2 = schedule[i - 2];
            const auto sigma0 = rotate_right(previous15, 7) ^ rotate_right(previous15, 18) ^
                                (previous15 >> 3U);
            const auto sigma1 = rotate_right(previous2, 17) ^ rotate_right(previous2, 19) ^
                                (previous2 >> 10U);
            schedule[i] = schedule[i - 16] + sigma0 + schedule[i - 7] + sigma1;
        }

        auto a = state_[0];
        auto b = state_[1];
        auto c = state_[2];
        auto d = state_[3];
        auto e = state_[4];
        auto f = state_[5];
        auto g = state_[6];
        auto h = state_[7];
        for (std::size_t i = 0; i < schedule.size(); ++i) {
            const auto sigma1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            const auto choose = (e & f) ^ (~e & g);
            const auto first = h + sigma1 + choose + round_constants[i] + schedule[i];
            const auto sigma0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto second = sigma0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + first;
            d = c;
            c = b;
            b = a;
            a = first + second;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    std::array<uint32_t, 8> state_{{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    }};
    std::array<uint8_t, 64> block_{};
    std::size_t used_ = 0;
    uint64_t total_bytes_ = 0;
};

}  // namespace

std::string sha256_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open SHA-256 input file: " + path);
    }

    Sha256 hash;
    std::array<char, 16384> buffer{};
    while (input.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) ||
           input.gcount() != 0) {
        hash.update(reinterpret_cast<const uint8_t*>(buffer.data()),
                    static_cast<std::size_t>(input.gcount()));
    }
    if (input.bad() || !input.eof()) {
        throw std::runtime_error("failed to read SHA-256 input file: " + path);
    }
    return hash.finish();
}

}  // namespace cansec
