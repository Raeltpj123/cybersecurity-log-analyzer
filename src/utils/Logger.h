#ifndef LOGGER_H
#define LOGGER_H

#include "../include/Common.h"
#include <string>
#include <fstream>
#include <mutex>

class Logger {
public:
    static Logger& getInstance();
    
    void initialize(const std::string& logFile, LogLevel minLevel = LogLevel::INFO);
    void log(LogLevel level, const std::string& message);
    void setMinLevel(LogLevel level) { minLogLevel = level; }
    
    // Convenience methods
    void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    void info(const std::string& message) { log(LogLevel::INFO, message); }
    void warning(const std::string& message) { log(LogLevel::WARNING, message); }
    void error(const std::string& message) { log(LogLevel::ERROR_LEVEL, message); }
    void critical(const std::string& message) { log(LogLevel::CRITICAL, message); }
    
private:
    Logger() = default;
    ~Logger();
    
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    std::string formatLogMessage(LogLevel level, const std::string& message);
    std::string levelToString(LogLevel level);
    
    std::ofstream logFile;
    LogLevel minLogLevel;
    std::mutex logMutex;
    bool initialized;
};

#endif // LOGGER_H
