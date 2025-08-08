#include "SecurityUtils.h"
#include "Logger.h"
#include <regex>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

std::string SecurityUtils::sanitizeInput(const std::string& input) {
    std::string sanitized = input;
    
    // Remove null bytes and control characters (except common whitespace)
    sanitized.erase(std::remove_if(sanitized.begin(), sanitized.end(), 
                    [](char c) { 
                        return (c < 32 && c != '\t' && c != '\n' && c != '\r') || c == 127; 
                    }), sanitized.end());
    
    // Truncate if too long
    sanitized = truncateIfNeeded(sanitized, Constants::MAX_LOG_ENTRY_SIZE);
    
    // Check for suspicious patterns
    if (containsSuspiciousPatterns(sanitized)) {
        Logger::getInstance().log(LogLevel::WARNING, 
            "Suspicious patterns detected in input, proceeding with caution");
    }
    
    return sanitized;
}

std::string SecurityUtils::sanitizeFilePath(const std::string& path) {
    std::string sanitizedPath = sanitizeInput(path);
    
    // Check for path traversal attempts
    if (checkPathTraversal(sanitizedPath)) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, 
            "Path traversal attempt detected: " + path);
        return ""; // Return empty string for invalid paths
    }
    
    // Remove potentially dangerous characters
    std::regex dangerousChars(R"([<>:"|?*])");
    sanitizedPath = std::regex_replace(sanitizedPath, dangerousChars, "_");
    
    return sanitizedPath;
}

std::string SecurityUtils::sanitizeURL(const std::string& url) {
    std::string sanitizedURL = sanitizeInput(url);
    
    if (!isValidURL(sanitizedURL)) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, 
            "Invalid URL format: " + url);
        return "http://localhost:11434"; // Default fallback
    }
    
    return sanitizedURL;
}

bool SecurityUtils::isValidLogEntry(const std::string& entry) {
    // Check basic constraints
    if (entry.empty() || entry.length() > Constants::MAX_LOG_ENTRY_SIZE) {
        return false;
    }
    
    // Check for excessive control characters
    size_t controlCharCount = 0;
    for (char c : entry) {
        if (c < 32 && c != '\t' && c != '\n' && c != '\r') {
            controlCharCount++;
        }
    }
    
    // Allow up to 5% control characters
    return (controlCharCount * 100 / entry.length()) <= 5;
}

bool SecurityUtils::isValidFilePath(const std::string& path) {
    if (path.empty() || path.length() > 260) { // Windows MAX_PATH
        return false;
    }
    
    // Check for invalid characters
    std::regex invalidChars(R"([<>:"|?*])");
    if (std::regex_search(path, invalidChars)) {
        return false;
    }
    
    return !checkPathTraversal(path);
}

bool SecurityUtils::isValidURL(const std::string& url) {
    // Basic URL validation
    std::regex urlPattern(R"(^https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^?\s]*)?(?:\?[^#\s]*)?(?:#[^\s]*)?$)");
    return std::regex_match(url, urlPattern);
}

bool SecurityUtils::containsSuspiciousPatterns(const std::string& input) {
    const auto& patterns = getSuspiciousPatterns();
    
    std::string lowerInput = input;
    std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(), ::tolower);
    
    for (const auto& pattern : patterns) {
        if (lowerInput.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool SecurityUtils::checkPathTraversal(const std::string& path) {
    const auto& patterns = getPathTraversalPatterns();
    
    for (const auto& pattern : patterns) {
        if (path.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool SecurityUtils::checkSQLInjection(const std::string& input) {
    const auto& patterns = getSQLInjectionPatterns();
    
    std::string lowerInput = input;
    std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(), ::tolower);
    
    for (const auto& pattern : patterns) {
        if (lowerInput.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool SecurityUtils::checkXSS(const std::string& input) {
    const auto& patterns = getXSSPatterns();
    
    std::string lowerInput = input;
    std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(), ::tolower);
    
    for (const auto& pattern : patterns) {
        if (lowerInput.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool SecurityUtils::checkCommandInjection(const std::string& input) {
    const auto& patterns = getCommandInjectionPatterns();
    
    for (const auto& pattern : patterns) {
        if (input.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool SecurityUtils::checkResourceLimits(size_t inputSize) {
    const size_t MAX_INPUT_SIZE = 10 * 1024 * 1024; // 10MB limit
    return inputSize <= MAX_INPUT_SIZE;
}

std::string SecurityUtils::truncateIfNeeded(const std::string& input, size_t maxLength) {
    if (input.length() <= maxLength) {
        return input;
    }
    
    Logger::getInstance().log(LogLevel::WARNING, 
        "Input truncated from " + std::to_string(input.length()) + 
        " to " + std::to_string(maxLength) + " characters");
    
    return input.substr(0, maxLength);
}

const std::vector<std::string>& SecurityUtils::getSuspiciousPatterns() {
    static std::vector<std::string> patterns = {
        "eval(",
        "exec(",
        "system(",
        "shell_exec",
        "passthru",
        "file_get_contents",
        "include(",
        "require(",
        "<script",
        "javascript:",
        "vbscript:",
        "onload=",
        "onerror=",
        "onclick="
    };
    return patterns;
}

const std::vector<std::string>& SecurityUtils::getPathTraversalPatterns() {
    static std::vector<std::string> patterns = {
        "../",
        "..\\",
        "..%2f",
        "..%5c",
        "%2e%2e%2f",
        "%2e%2e%5c"
    };
    return patterns;
}

const std::vector<std::string>& SecurityUtils::getSQLInjectionPatterns() {
    static std::vector<std::string> patterns = {
        "union select",
        "drop table",
        "insert into",
        "delete from",
        "update set",
        "exec(",
        "execute(",
        "sp_",
        "xp_",
        "' or '1'='1",
        "' or 1=1",
        "admin'--",
        "admin'/*"
    };
    return patterns;
}

const std::vector<std::string>& SecurityUtils::getXSSPatterns() {
    static std::vector<std::string> patterns = {
        "<script>",
        "</script>",
        "javascript:",
        "vbscript:",
        "onload=",
        "onerror=",
        "onclick=",
        "onmouseover=",
        "onfocus=",
        "alert(",
        "document.cookie",
        "document.location"
    };
    return patterns;
}

const std::vector<std::string>& SecurityUtils::getCommandInjectionPatterns() {
    static std::vector<std::string> patterns = {
        ";",
        "&&",
        "||",
        "|",
        "`",
        "$(",
        "$()",
        "${",
        "cat /",
        "ls -",
        "rm -",
        "chmod ",
        "wget ",
        "curl "
    };
    return patterns;
}

std::string SecurityUtils::base64Encode(const std::string& input) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0, valb = -6;
    
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        encoded.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    
    return encoded;
}

std::string SecurityUtils::urlEncode(const std::string& input) {
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex;
    
    for (char c : input) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << std::uppercase;
            encoded << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
            encoded << std::nouppercase;
        }
    }
    
    return encoded.str();
}
