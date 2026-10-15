#include "cansec/socketcan.hpp"

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>

namespace cansec {

namespace {

std::system_error make_errno_error(const std::string& message) {
    return std::system_error(errno, std::generic_category(), message);
}

void enable_receive_timestamps(int socket_fd) {
    const int enable = 1;
#if defined(SO_TIMESTAMPNS) && defined(SCM_TIMESTAMPNS)
    if (setsockopt(socket_fd, SOL_SOCKET, SO_TIMESTAMPNS, &enable, sizeof(enable)) == 0) {
        return;
    }
    if (errno != ENOPROTOOPT && errno != EINVAL && errno != EOPNOTSUPP) {
        throw make_errno_error("setsockopt(SO_TIMESTAMPNS) failed");
    }
#endif
    // Older kernels may only offer microsecond ancillary timestamps. Both
    // options associate the timestamp with the received packet itself.
    if (setsockopt(socket_fd, SOL_SOCKET, SO_TIMESTAMP, &enable, sizeof(enable)) < 0) {
        throw make_errno_error("setsockopt(SO_TIMESTAMP) failed; packet receive timestamps are required");
    }
}

uint64_t timestamp_to_us(int64_t seconds, int64_t fraction, int64_t units_per_second) {
    if (seconds < 0 || fraction < 0 || fraction >= units_per_second) {
        throw std::runtime_error("invalid kernel CAN receive timestamp");
    }
    const auto microseconds = static_cast<uint64_t>(fraction / (units_per_second / 1000000));
    const auto whole_seconds = static_cast<uint64_t>(seconds);
    if (whole_seconds > (std::numeric_limits<uint64_t>::max() - microseconds) / 1000000ULL) {
        throw std::overflow_error("kernel CAN receive timestamp exceeds uint64 microseconds");
    }
    return whole_seconds * 1000000ULL + microseconds;
}

uint64_t receive_timestamp_us(msghdr& message) {
    std::optional<uint64_t> timestamp;
    for (auto* control = CMSG_FIRSTHDR(&message); control != nullptr;
         control = CMSG_NXTHDR(&message, control)) {
        if (control->cmsg_level != SOL_SOCKET) continue;
        std::optional<uint64_t> decoded;
#if defined(SCM_TIMESTAMPNS)
        if (control->cmsg_type == SCM_TIMESTAMPNS) {
            if (control->cmsg_len < CMSG_LEN(sizeof(timespec))) {
                throw std::runtime_error("incomplete nanosecond CAN receive timestamp");
            }
            timespec value{};
            std::memcpy(&value, CMSG_DATA(control), sizeof(value));
            decoded = timestamp_to_us(value.tv_sec, value.tv_nsec, 1000000000);
        } else
#endif
        if (control->cmsg_type == SCM_TIMESTAMP) {
            if (control->cmsg_len < CMSG_LEN(sizeof(timeval))) {
                throw std::runtime_error("incomplete microsecond CAN receive timestamp");
            }
            timeval value{};
            std::memcpy(&value, CMSG_DATA(control), sizeof(value));
            decoded = timestamp_to_us(value.tv_sec, value.tv_usec, 1000000);
        }
        if (decoded) {
            if (timestamp) throw std::runtime_error("multiple kernel CAN receive timestamps");
            timestamp = decoded;
        }
    }
    if (!timestamp) throw std::runtime_error("kernel CAN receive timestamp is missing");
    return *timestamp;
}

}  // namespace

int open_can_socket(const std::string& interface_name, bool recv_own_msgs) {
    if (interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
        throw std::invalid_argument("interface name must contain 1 to 15 bytes");
    }

    int socket_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (socket_fd < 0) {
        throw make_errno_error("socket(PF_CAN, SOCK_RAW, CAN_RAW) failed");
    }

    try {
        enable_receive_timestamps(socket_fd);
    } catch (...) {
        close(socket_fd);
        throw;
    }

    if (recv_own_msgs) {
        int enable = 1;
        if (setsockopt(socket_fd, SOL_CAN_RAW, CAN_RAW_RECV_OWN_MSGS,
                       &enable, sizeof(enable)) < 0) {
            close(socket_fd);
            throw make_errno_error("setsockopt(CAN_RAW_RECV_OWN_MSGS) failed");
        }
    }

    ifreq ifr{};
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) < 0) {
        close(socket_fd);
        throw make_errno_error("ioctl(SIOCGIFINDEX) failed for interface " + interface_name);
    }

    sockaddr_can addr{};
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(socket_fd);
        throw make_errno_error("bind() failed for interface " + interface_name);
    }

    return socket_fd;
}

void set_socket_read_timeout_ms(int socket_fd, int timeout_ms) {
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        throw make_errno_error("setsockopt(SO_RCVTIMEO) failed");
    }
}

std::optional<CanFrameRecord> read_can_frame(int socket_fd, const std::string& interface_name) {
    can_frame frame{};
    alignas(cmsghdr) std::array<unsigned char,
        CMSG_SPACE(sizeof(timespec)) + CMSG_SPACE(sizeof(timeval))> control{};
    iovec data{};
    data.iov_base = &frame;
    data.iov_len = sizeof(frame);
    msghdr message{};
    message.msg_iov = &data;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();

    const ssize_t nbytes = recvmsg(socket_fd, &message, 0);

    if (nbytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::nullopt;
        }
        throw make_errno_error("recvmsg() failed");
    }

    if (static_cast<size_t>(nbytes) != sizeof(can_frame) || (message.msg_flags & MSG_TRUNC) != 0) {
        throw std::runtime_error("incomplete CAN frame read");
    }
    if ((message.msg_flags & MSG_CTRUNC) != 0) {
        throw std::runtime_error("truncated CAN receive timestamp metadata");
    }

    // CanFrameRecord and the log format represent data frames only; preserving
    // RTR or error frames here would mislabel them as ordinary payload data.
    if ((frame.can_id & (CAN_RTR_FLAG | CAN_ERR_FLAG)) != 0) {
        return std::nullopt;
    }

    CanFrameRecord record;
    record.timestamp_us = receive_timestamp_us(message);
    record.interface_name = interface_name;

    const bool is_extended = (frame.can_id & CAN_EFF_FLAG) != 0;
    record.id_type = is_extended ? IdType::Extended29 : IdType::Standard11;
    record.can_id = is_extended ? (frame.can_id & CAN_EFF_MASK)
                                : (frame.can_id & CAN_SFF_MASK);

    record.dlc = frame.can_dlc;
    for (uint8_t i = 0; i < record.dlc && i < 8; ++i) {
        record.data[i] = frame.data[i];
    }

    return record;
}

void write_can_frame(int socket_fd, const CanFrameRecord& record) {
    can_frame frame{};
    switch (record.id_type) {
        case IdType::Standard11:
            if (record.can_id > CAN_SFF_MASK) {
                throw std::invalid_argument("standard CAN ID exceeds 11 bits");
            }
            frame.can_id = record.can_id;
            break;
        case IdType::Extended29:
            if (record.can_id > CAN_EFF_MASK) {
                throw std::invalid_argument("extended CAN ID exceeds 29 bits");
            }
            frame.can_id = record.can_id | CAN_EFF_FLAG;
            break;
        default:
            throw std::invalid_argument("invalid CAN ID type");
    }
    if (record.dlc > 8) {
        throw std::invalid_argument("DLC must be between 0 and 8");
    }
    frame.can_dlc = record.dlc;
    for (uint8_t i = 0; i < record.dlc; ++i) {
        frame.data[i] = record.data[i];
    }
    const ssize_t nbytes = write(socket_fd, &frame, sizeof(frame));
    if (nbytes < 0) {
        throw make_errno_error("write() failed");
    }
    if (static_cast<size_t>(nbytes) != sizeof(frame)) {
        throw std::runtime_error("incomplete CAN frame write");
    }
}

void close_socket(int socket_fd) {
    if (socket_fd >= 0) {
        close(socket_fd);
    }
}

}  // namespace cansec
