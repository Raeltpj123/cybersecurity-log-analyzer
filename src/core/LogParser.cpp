#include "LogParser.h"
#include "../utils/Logger.h"
#include "../utils/SecurityUtils.h"
#include <sstream>
#include <regex>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

LogParser::LogParser() : 
    maxEntriesPerBatch(Constants::MAX_ENTRIES_PER_BATCH),
    maxLogLineSize(Constants::MAX_LOG_ENTRY_SIZE),
    totalEntriesParsed(0),
    invalidEntriesSkipped(0) {
}

LogParser::~LogParser() {
    Logger::getInstance().log(LogLevel::INFO, 
        "LogParser stats - Parsed: " + std::to_string(totalEntriesParsed) + 
        ", Skipped: " + std::to_string(invalidEntriesSkipped));
}

std::vector<LogEntry> LogParser::parseFile(const std::string& filename, LogFormat format) {
    Logger::getInstance().log(LogLevel::INFO, "Starting to parse file: " + filename);
    
    // Auto-detect format if not specified
    if (format == LogFormat::UNKNOWN) {
        format = detectFormat(filename);
        Logger::getInstance().log(LogLevel::DEBUG, "Auto-detected format: " + Utils::formatToString(format));
    }
    
    // Validate file access
    std::ifstream file(filename);
    if (!file.is_open()) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Cannot open file: " + filename);
        return {};
    }
    file.close();
    
    // Parse based on detected/specified format
    switch (format) {
        case LogFormat::SYSLOG:
            return parseSyslog(filename);
        case LogFormat::WINDOWS_EVENT:
            return parseWindowsEvent(filename);
        case LogFormat::JSON:
            return parseJSON(filename);
        case LogFormat::CSV:
            return parseCSV(filename);
        default:
            Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Unsupported log format");
            return {};
    }
}

LogFormat LogParser::detectFormat(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return LogFormat::UNKNOWN;
    }
    
    std::string firstLine;
    std::getline(file, firstLine);
    file.close();
    
    // Check for JSON format
    if (firstLine.front() == '{' && firstLine.back() == '}') {
        return LogFormat::JSON;
    }
    
    // Check for CSV format (contains commas and headers)
    if (firstLine.find(',') != std::string::npos && 
        (firstLine.find("timestamp") != std::string::npos || 
         firstLine.find("time") != std::string::npos)) {
        return LogFormat::CSV;
    }
    
    // Check for Windows Event Log format (XML-like or structured)
    if (firstLine.find("EventID") != std::string::npos || 
        firstLine.find("Event") != std::string::npos) {
        return LogFormat::WINDOWS_EVENT;
    }
    
    // Default to syslog format
    return LogFormat::SYSLOG;
}

std::vector<LogEntry> LogParser::parseSyslog(const std::string& filename) {
    std::vector<LogEntry> entries;
    std::ifstream file(filename);
    std::string line;
    
    while (std::getline(file, line) && entries.size() < maxEntriesPerBatch) {
        if (!isValidLogLine(line)) {
            invalidEntriesSkipped++;
            continue;
        }
        
        LogEntry entry = parseSyslogLine(sanitizeLogLine(line));
        if (validateLogEntry(entry)) {
            entries.push_back(entry);
            totalEntriesParsed++;
        } else {
            invalidEntriesSkipped++;
        }
    }
    
    return entries;
}

LogEntry LogParser::parseSyslogLine(const std::string& line) {
    LogEntry entry(line);
    
    // Regex pattern for standard syslog format:
    // Month Day HH:MM:SS hostname process[pid]: message
    std::regex syslogPattern(R"((\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.+))");
    std::smatch matches;
    
    if (std::regex_search(line, matches, syslogPattern)) {
        // Parse timestamp (approximate - using current year)
        std::string timestampStr = matches[1].str();
        entry.timestamp = parseTimestamp(timestampStr, "%b %d %H:%M:%S");
        
        // Extract components
        entry.source = matches[2].str();
        entry.level = "INFO"; // Default level
        entry.message = matches[4].str();
        
        // Extract additional metadata
        std::string process = matches[3].str();
        entry.metadata["process"] = process;
        
        // Detect log level from message content
        std::string upperMsg = entry.message;
        std::transform(upperMsg.begin(), upperMsg.end(), upperMsg.begin(), ::toupper);
        
        if (upperMsg.find("ERROR") != std::string::npos || upperMsg.find("FAIL") != std::string::npos) {
            entry.level = "ERROR";
        } else if (upperMsg.find("WARN") != std::string::npos) {
            entry.level = "WARNING";
        } else if (upperMsg.find("DEBUG") != std::string::npos) {
            entry.level = "DEBUG";
        }
        
    } else {
        // If regex doesn't match, store as raw message
        entry.message = line;
        entry.timestamp = std::chrono::system_clock::now();
        entry.source = "unknown";
        entry.level = "INFO";
    }
    
    return entry;
}

std::vector<LogEntry> LogParser::parseJSON(const std::string& filename) {
    std::vector<LogEntry> entries;
    std::ifstream file(filename);
    std::string line;
    
    while (std::getline(file, line) && entries.size() < maxEntriesPerBatch) {
        if (!isValidLogLine(line)) {
            invalidEntriesSkipped++;
            continue;
        }
        
        try {
            LogEntry entry = parseWindowsEventLine(sanitizeLogLine(line));
            if (validateLogEntry(entry)) {
                entries.push_back(entry);
                totalEntriesParsed++;
            } else {
                invalidEntriesSkipped++;
            }
        } catch (const std::exception& e) {
            Logger::getInstance().log(LogLevel::WARNING, "Failed to parse JSON line: " + std::string(e.what()));
            invalidEntriesSkipped++;
        }
    }
    
    return entries;
}

LogEntry LogParser::parseWindowsEventLine(const std::string& jsonLine) {
    LogEntry entry(jsonLine);
    
    try {
        json j = json::parse(jsonLine);
        
        // Extract standard fields
        if (j.contains("TimeCreated")) {
            std::string timeStr = j["TimeCreated"];
            entry.timestamp = parseTimestamp(timeStr, "%Y-%m-%dT%H:%M:%S");
        } else {
            entry.timestamp = std::chrono::system_clock::now();
        }
        
        entry.source = j.value("Computer", "unknown");
        entry.level = j.value("Level", "Information");
        entry.message = j.value("Message", "");
        
        // Extract Windows Event specific metadata
        if (j.contains("EventID")) {
            entry.metadata["EventID"] = std::to_string(j["EventID"].get<int>());
        }
        
        if (j.contains("Channel")) {
            entry.metadata["Channel"] = j["Channel"];
        }
        
        if (j.contains("Provider")) {
            entry.metadata["Provider"] = j["Provider"];
        }
        
        if (j.contains("ProcessId")) {
            entry.metadata["ProcessId"] = std::to_string(j["ProcessId"].get<int>());
        }
        
    } catch (const json::exception& e) {
        Logger::getInstance().log(LogLevel::WARNING, "JSON parsing error: " + std::string(e.what()));
        // Fall back to raw storage
        entry.message = jsonLine;
        entry.timestamp = std::chrono::system_clock::now();
        entry.source = "json_parse_error";
        entry.level = "ERROR";
    }
    
    return entry;
}

std::vector<LogEntry> LogParser::parseCSV(const std::string& filename) {
    std::vector<LogEntry> entries;
    std::ifstream file(filename);
    std::string line;
    std::vector<std::string> headers;
    
    // Read header line
    if (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string header;
        while (std::getline(ss, header, ',')) {
            headers.push_back(header);
        }
    }
    
    // Parse data lines
    while (std::getline(file, line) && entries.size() < maxEntriesPerBatch) {
        if (!isValidLogLine(line)) {
            invalidEntriesSkipped++;
            continue;
        }
        
        LogEntry entry = parseCSVLine(sanitizeLogLine(line), headers);
        if (validateLogEntry(entry)) {
            entries.push_back(entry);
            totalEntriesParsed++;
        } else {
            invalidEntriesSkipped++;
        }
    }
    
    return entries;
}

LogEntry LogParser::parseCSVLine(const std::string& line, const std::vector<std::string>& headers) {
    LogEntry entry(line);
    
    std::stringstream ss(line);
    std::string field;
    std::vector<std::string> fields;
    
    // Parse CSV fields
    while (std::getline(ss, field, ',')) {
        fields.push_back(field);
    }
    
    // Map fields to LogEntry based on headers
    for (size_t i = 0; i < headers.size() && i < fields.size(); ++i) {
        std::string header = headers[i];
        std::string value = fields[i];
        
        // Remove quotes if present
        if (value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.length() - 2);
        }
        
        if (header == "timestamp" || header == "time") {
            entry.timestamp = parseTimestamp(value, "%Y-%m-%d %H:%M:%S");
        } else if (header == "source" || header == "host") {
            entry.source = value;
        } else if (header == "level" || header == "severity") {
            entry.level = value;
        } else if (header == "message" || header == "description") {
            entry.message = value;
        } else {
            entry.metadata[header] = value;
        }
    }
    
    // Set defaults if not found
    if (entry.source.empty()) entry.source = "csv";
    if (entry.level.empty()) entry.level = "INFO";
    if (entry.message.empty()) entry.message = line;
    
    return entry;
}

std::vector<LogEntry> LogParser::parseWindowsEvent(const std::string& filename) {
    // For now, treat Windows Event logs as JSON format
    return parseJSON(filename);
}

bool LogParser::isValidLogLine(const std::string& line) {
    return !line.empty() && 
           line.length() <= maxLogLineSize &&
           SecurityUtils::isValidLogEntry(line);
}

std::string LogParser::sanitizeLogLine(const std::string& line) {
    return SecurityUtils::sanitizeInput(line);
}

bool LogParser::validateLogEntry(const LogEntry& entry) {
    return !entry.message.empty() && 
           !entry.source.empty() &&
           entry.message.length() <= maxLogLineSize;
}

std::chrono::system_clock::time_point LogParser::parseTimestamp(const std::string& timestamp, const std::string& format) {
    std::tm tm = {};
    std::istringstream ss(timestamp);
    
    // Try to parse with the given format
    if (format == "%b %d %H:%M:%S") {
        // Syslog format: "Jan 15 10:23:45"
        ss >> std::get_time(&tm, "%b %d %H:%M:%S");
        if (!ss.fail()) {
            tm.tm_year = 125; // 2025
            return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        }
    } else if (format == "%Y-%m-%dT%H:%M:%S") {
        // ISO format: "2025-01-15T10:23:45"
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (!ss.fail()) {
            return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        }
    } else if (format == "%Y-%m-%d %H:%M:%S") {
        // Standard format: "2025-01-15 10:23:45"
        ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
        if (!ss.fail()) {
            return std::chrono::system_clock::from_time_t(std::mktime(&tm));
        }
    }
    
    // If parsing fails, return current time
    return std::chrono::system_clock::now();
}

std::vector<LogEntry> LogParser::loadSampleData() {
    std::vector<LogEntry> sampleEntries;
    
    // Sample syslog entries
    LogEntry entry1;
    entry1.timestamp = std::chrono::system_clock::now();
    entry1.source = "server1";
    entry1.level = "ERROR";
    entry1.message = "Failed password for root from 192.168.1.100 port 22 ssh2";
    entry1.metadata["process"] = "sshd[1234]";
    sampleEntries.push_back(entry1);
    
    LogEntry entry2;
    entry2.timestamp = std::chrono::system_clock::now();
    entry2.source = "server1";
    entry2.level = "ERROR";
    entry2.message = "Failed password for admin from 192.168.1.100 port 22 ssh2";
    entry2.metadata["process"] = "sshd[1234]";
    sampleEntries.push_back(entry2);
    
    LogEntry entry3;
    entry3.timestamp = std::chrono::system_clock::now();
    entry3.source = "firewall";
    entry3.level = "WARNING";
    entry3.message = "iptables: DROP IN=eth0 OUT= SRC=10.0.0.5 DST=192.168.1.1";
    entry3.metadata["process"] = "kernel";
    sampleEntries.push_back(entry3);
    
    LogEntry entry4;
    entry4.timestamp = std::chrono::system_clock::now();
    entry4.source = "webserver";
    entry4.level = "INFO";
    entry4.message = "GET /admin HTTP/1.1 404 from 203.0.113.5";
    entry4.metadata["process"] = "httpd";
    sampleEntries.push_back(entry4);
    
    LogEntry entry5;
    entry5.timestamp = std::chrono::system_clock::now();
    entry5.source = "server1";
    entry5.level = "CRITICAL";
    entry5.message = "Multiple failed login attempts detected - potential brute force attack";
    entry5.metadata["process"] = "security";
    sampleEntries.push_back(entry5);
    
    Logger::getInstance().log(LogLevel::INFO, "Loaded " + std::to_string(sampleEntries.size()) + " sample log entries");
    
    return sampleEntries;
}
