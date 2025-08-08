#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <iostream>
#include <memory>

// Project version
#define VERSION_MAJOR 1
#define VERSION_MINOR 0
#define VERSION_PATCH 0

// Log levels for internal logging
enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR_LEVEL = 3,  // Renamed to avoid Windows ERROR macro conflict
    CRITICAL = 4
};

// Supported log formats
enum class LogFormat {
    SYSLOG,
    WINDOWS_EVENT,
    JSON,
    CSV,
    UNKNOWN
};

// Threat severity levels
enum class ThreatLevel {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

// Configuration structure
struct Config {
    std::string inputFile;
    std::string outputFile;
    LogFormat format;
    std::string ollamaModel;
    std::string ollamaUrl;
    std::string customPrompt;
    bool testMode;
    bool verbose;
    
    Config() : 
        format(LogFormat::UNKNOWN),
        ollamaModel("llama3"),
        ollamaUrl("http://localhost:11434"),
        testMode(false),
        verbose(false) {}
};

// Log entry structure
struct LogEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string source;
    std::string level;
    std::string message;
    std::string rawEntry;
    std::map<std::string, std::string> metadata;
    
    LogEntry() = default;
    LogEntry(const std::string& raw) : rawEntry(raw) {}
};

// Threat detection result
struct ThreatIndicator {
    ThreatLevel severity;
    std::string type;
    std::string description;
    std::string sourceIP;
    std::string targetIP;
    std::vector<std::string> indicators;
    std::vector<std::string> recommendations;
    double confidence;
    
    ThreatIndicator() : severity(ThreatLevel::LOW), confidence(0.0) {}
};

// Analysis report structure
struct AnalysisReport {
    std::chrono::system_clock::time_point generatedAt;
    std::string modelUsed;
    std::vector<ThreatIndicator> threats;
    std::string summary;
    std::string detailedAnalysis;
    std::vector<std::string> recommendations;
    std::map<std::string, int> statistics;
    
    AnalysisReport() {
        generatedAt = std::chrono::system_clock::now();
    }
};

// OLLAMA API request structure
struct OllamaRequest {
    std::string model;
    std::string prompt;
    bool stream;
    std::map<std::string, double> options;
    
    OllamaRequest() : stream(false) {}
};

// OLLAMA API response structure
struct OllamaResponse {
    std::string response;
    bool done;
    std::string error;
    std::map<std::string, std::string> metadata;
    
    OllamaResponse() : done(false) {}
};

// Utility functions
namespace Utils {
    std::string getCurrentTimestamp();
    std::string severityToString(ThreatLevel level);
    ThreatLevel stringToSeverity(const std::string& level);
    std::string formatToString(LogFormat format);
    LogFormat stringToFormat(const std::string& format);
    bool isValidIP(const std::string& ip);
    std::string sanitizeInput(const std::string& input);
}

// Constants
namespace Constants {
    const int MAX_LOG_ENTRY_SIZE = 8192;
    const int MAX_ENTRIES_PER_BATCH = 1000;
    const int OLLAMA_TIMEOUT_SECONDS = 30;
    const std::string DEFAULT_OUTPUT_FILE = "cybersec_analysis_report.txt";
    const std::string LOG_FILE = "cybersec_tool.log";
}

#endif // COMMON_H
