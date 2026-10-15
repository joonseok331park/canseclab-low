#include "cansec/alert_json.hpp"

#include <iomanip>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace cansec {
namespace {

const char* rule_name(AlertRule rule) {
    switch (rule) {
        case AlertRule::UnknownId: return "UNKNOWN_ID";
        case AlertRule::DlcMismatch: return "DLC_MISMATCH";
        case AlertRule::PeriodViolation: return "PERIOD_VIOLATION";
        case AlertRule::RateSpike: return "RATE_SPIKE";
        case AlertRule::FixedByteViolation: return "FIXED_BYTE_VIOLATION";
        case AlertRule::ReplayBurst: return "REPLAY_BURST";
    }
    throw std::invalid_argument("invalid alert rule");
}

const char* severity_name(Severity severity) {
    switch (severity) {
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
    }
    throw std::invalid_argument("invalid alert severity");
}

std::string quote_json(const std::string& value) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result = "\"";
    for (std::size_t i = 0; i < value.size();) {
        const auto c = static_cast<unsigned char>(value[i]);
        if (c < 0x80) {
            if (c == '"' || c == '\\') {
                result += '\\';
                result += static_cast<char>(c);
            } else if (c < 0x20) {
                result += "\\u00";
                result += hex[c >> 4];
                result += hex[c & 0x0F];
            } else {
                result += static_cast<char>(c);
            }
            ++i;
            continue;
        }
        // Preserve valid UTF-8. Reject overlong sequences, surrogates, isolated
        // continuation bytes and values beyond Unicode rather than writing bad JSON.
        const std::size_t length = c >= 0xC2 && c <= 0xDF ? 2 :
                                   c >= 0xE0 && c <= 0xEF ? 3 :
                                   c >= 0xF0 && c <= 0xF4 ? 4 : 0;
        if (length == 0 || value.size() - i < length) {
            throw std::invalid_argument("alert string is not valid UTF-8");
        }
        uint32_t codepoint = c & (length == 2 ? 0x1FU : length == 3 ? 0x0FU : 0x07U);
        for (std::size_t j = 1; j < length; ++j) {
            const auto next = static_cast<unsigned char>(value[i + j]);
            if ((next & 0xC0U) != 0x80U) {
                throw std::invalid_argument("alert string is not valid UTF-8");
            }
            codepoint = (codepoint << 6) | (next & 0x3FU);
        }
        const uint32_t minimum = length == 2 ? 0x80U : length == 3 ? 0x800U : 0x10000U;
        if (codepoint < minimum || codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            throw std::invalid_argument("alert string is not valid UTF-8");
        }
        result.append(value, i, length);
        i += length;
    }
    result += '"';
    return result;
}

}  // namespace

std::string format_alert_json(const Alert& alert) {
    if (alert.id_type != IdType::Standard11 && alert.id_type != IdType::Extended29) {
        throw std::invalid_argument("invalid alert ID type");
    }
    const auto maximum = alert.id_type == IdType::Standard11 ? 0x7FFU : 0x1FFFFFFFU;
    if (alert.can_id > maximum || alert.dlc > alert.data.size()) {
        throw std::invalid_argument("invalid alert CAN ID or DLC");
    }
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "{\"capture_ts_us\":" << alert.capture_ts_us
           << ",\"alert_ts_us\":" << alert.alert_ts_us
           << ",\"if\":" << quote_json(alert.interface_name)
           << ",\"rule\":\"" << rule_name(alert.rule)
           << "\",\"severity\":\"" << severity_name(alert.severity)
           << "\",\"can_id\":\"0x" << std::uppercase << std::hex << alert.can_id
           << "\",\"id_type\":\"" << (alert.id_type == IdType::Standard11 ? "standard" : "extended")
           << "\",\"dlc\":" << std::dec << static_cast<unsigned>(alert.dlc)
           << ",\"data\":\"" << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < alert.dlc; ++i) {
        output << std::setw(2) << static_cast<unsigned>(alert.data[i]);
    }
    output << "\",\"detail\":" << quote_json(alert.detail) << '}';
    return output.str();
}

}  // namespace cansec
