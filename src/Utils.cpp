#include "Common.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <regex>

namespace Utils {

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string severityToString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::LOW:      return "LOW";
        case ThreatLevel::MEDIUM:   return "MEDIUM";
        case ThreatLevel::HIGH:     return "HIGH";
        case ThreatLevel::CRITICAL: return "CRITICAL";
        default:                    return "UNKNOWN";
    }
}

ThreatLevel stringToSeverity(const std::string& level) {
    std::string upperLevel = level;
    std::transform(upperLevel.begin(), upperLevel.end(), upperLevel.begin(), ::toupper);
    
    if (upperLevel == "CRITICAL") return ThreatLevel::CRITICAL;
    if (upperLevel == "HIGH") return ThreatLevel::HIGH;
    if (upperLevel == "MEDIUM") return ThreatLevel::MEDIUM;
    if (upperLevel == "LOW") return ThreatLevel::LOW;
    
    return ThreatLevel::LOW; // Default
}

std::string formatToString(LogFormat format) {
    switch (format) {
        case LogFormat::SYSLOG:        return "syslog";
        case LogFormat::WINDOWS_EVENT: return "windows";
        case LogFormat::JSON:          return "json";
        case LogFormat::CSV:           return "csv";
        default:                       return "unknown";
    }
}

LogFormat stringToFormat(const std::string& format) {
    std::string lowerFormat = format;
    std::transform(lowerFormat.begin(), lowerFormat.end(), lowerFormat.begin(), ::tolower);
    
    if (lowerFormat == "syslog") return LogFormat::SYSLOG;
    if (lowerFormat == "windows" || lowerFormat == "windows_event") return LogFormat::WINDOWS_EVENT;
    if (lowerFormat == "json") return LogFormat::JSON;
    if (lowerFormat == "csv") return LogFormat::CSV;
    
    return LogFormat::UNKNOWN;
}

bool isValidIP(const std::string& ip) {
    std::regex ipPattern(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
    if (!std::regex_match(ip, ipPattern)) {
        return false;
    }
    
    // Check each octet is 0-255
    std::istringstream iss(ip);
    std::string octet;
    
    for (int i = 0; i < 4; ++i) {
        if (!std::getline(iss, octet, '.')) {
            return false;
        }
        
        try {
            int value = std::stoi(octet);
            if (value < 0 || value > 255) {
                return false;
            }
        } catch (const std::exception&) {
            return false;
        }
    }
    
    return true;
}

std::string sanitizeInput(const std::string& input) {
    std::string sanitized = input;
    
    // Remove null bytes and dangerous control characters
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(), 
                    [](char c) { 
                        return c == '\0' || (c < 32 && c != '\t' && c != '\n' && c != '\r'); 
                    }), sanitized.end());
    
    // Limit length
    if (sanitized.length() > Constants::MAX_LOG_ENTRY_SIZE) {
        sanitized = sanitized.substr(0, Constants::MAX_LOG_ENTRY_SIZE);
    }
    
    return sanitized;
}

} // namespace Utils
