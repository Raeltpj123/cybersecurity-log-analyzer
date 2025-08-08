#ifndef LOGPARSER_H
#define LOGPARSER_H

#include "../include/Common.h"
#include <vector>
#include <string>
#include <fstream>

class LogParser {
public:
    LogParser();
    ~LogParser();
    
    // Main parsing function
    std::vector<LogEntry> parseFile(const std::string& filename, LogFormat format = LogFormat::UNKNOWN);
    
    // Format-specific parsers
    std::vector<LogEntry> parseSyslog(const std::string& filename);
    std::vector<LogEntry> parseWindowsEvent(const std::string& filename);
    std::vector<LogEntry> parseJSON(const std::string& filename);
    std::vector<LogEntry> parseCSV(const std::string& filename);
    
    // Auto-detect format
    LogFormat detectFormat(const std::string& filename);
    
    // Load sample data for testing
    std::vector<LogEntry> loadSampleData();
    
    // Utility functions
    bool validateLogEntry(const LogEntry& entry);
    size_t getMaxEntriesPerBatch() const { return maxEntriesPerBatch; }
    void setMaxEntriesPerBatch(size_t count) { maxEntriesPerBatch = count; }
    
private:
    // Internal parsing helpers
    LogEntry parseSyslogLine(const std::string& line);
    LogEntry parseWindowsEventLine(const std::string& jsonLine);
    LogEntry parseCSVLine(const std::string& line, const std::vector<std::string>& headers);
    
    // Validation and sanitization
    bool isValidLogLine(const std::string& line);
    std::string sanitizeLogLine(const std::string& line);
    
    // Timestamp parsing
    std::chrono::system_clock::time_point parseTimestamp(const std::string& timestamp, const std::string& format);
    
    // Configuration
    size_t maxEntriesPerBatch;
    size_t maxLogLineSize;
    
    // Statistics
    size_t totalEntriesParsed;
    size_t invalidEntriesSkipped;
};

#endif // LOGPARSER_H
