#include "Logger.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

void Logger::initialize(const std::string& logFileName, LogLevel minLevel) {
    std::lock_guard<std::mutex> lock(logMutex);
    
    if (logFile.is_open()) {
        logFile.close();
    }
    
    logFile.open(logFileName, std::ios::app);
    minLogLevel = minLevel;
    initialized = logFile.is_open();
    
    if (initialized) {
        log(LogLevel::INFO, "Logger initialized successfully");
    } else {
        std::cerr << "Failed to initialize logger with file: " << logFileName << std::endl;
    }
}

void Logger::log(LogLevel level, const std::string& message) {
    if (static_cast<int>(level) < static_cast<int>(minLogLevel)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(logMutex);
    
    std::string formattedMessage = formatLogMessage(level, message);
    
    // Always output to console for important messages
    if (level >= LogLevel::WARNING) {
        std::cerr << formattedMessage << std::endl;
    } else if (level == LogLevel::INFO) {
        std::cout << formattedMessage << std::endl;
    }
    
    // Write to log file if available
    if (initialized && logFile.is_open()) {
        logFile << formattedMessage << std::endl;
        logFile.flush();
    }
}

std::string Logger::formatLogMessage(LogLevel level, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << " [" << levelToString(level) << "] " << message;
    
    return oss.str();
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARNING:  return "WARN";
        case LogLevel::ERROR_LEVEL:    return "ERROR";
        case LogLevel::CRITICAL: return "CRIT";
        default:                 return "UNKNOWN";
    }
}
