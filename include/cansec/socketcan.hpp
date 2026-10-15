#pragma once

#include <optional>
#include <string>

#include "cansec/types.hpp"

namespace cansec {
int open_can_socket(const std::string& interface_name, bool recv_own_msgs = false);

void set_socket_read_timeout_ms(int socket_fd, int timeout_ms);

std::optional<CanFrameRecord> read_can_frame(int socket_fd, const std::string& interface_name);

// Sends one Classical CAN data frame. Errors, including EINTR, are returned to the caller.
void write_can_frame(int socket_fd, const CanFrameRecord& record);

void close_socket(int socket_fd);

}  // namespace cansec
