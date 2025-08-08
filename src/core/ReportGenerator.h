#ifndef REPORTGENERATOR_H
#define REPORTGENERATOR_H

#include "../include/Common.h"
#include <vector>
#include <string>

class ReportGenerator {
public:
    ReportGenerator();
    ~ReportGenerator();
    
    // Main report generation functions
    bool generateReport(const AnalysisReport& analysis, 
                       const std::vector<LogEntry>& entries, 
                       const std::string& outputFile);
    
    bool generateHTMLReport(const AnalysisReport& analysis, 
                           const std::vector<LogEntry>& entries, 
                           const std::string& outputFile);
    
    bool generateJSONReport(const AnalysisReport& analysis, 
                           const std::vector<LogEntry>& entries, 
                           const std::string& outputFile);
    
    // Report sections
    std::string generateExecutiveSummary(const AnalysisReport& analysis);
    std::string generateThreatDetails(const std::vector<ThreatIndicator>& threats);
    std::string generateRecommendations(const std::vector<std::string>& recommendations);
    std::string generateStatistics(const std::map<std::string, int>& stats);
    std::string generateLogSample(const std::vector<LogEntry>& entries, size_t maxEntries = 10);
    
    // Formatting utilities
    std::string formatTimestamp(const std::chrono::system_clock::time_point& timestamp);
    std::string formatThreatLevel(ThreatLevel level);
    std::string escapeHTML(const std::string& input);
    std::string escapeJSON(const std::string& input);
    
    // Configuration
    void setIncludeLogSamples(bool include) { includeLogSamples = include; }
    void setMaxLogSamples(size_t max) { maxLogSamples = max; }
    void setIncludeStatistics(bool include) { includeStatistics = include; }
    
private:
    // Internal formatting helpers
    std::string generateHeader();
    std::string generateFooter();
    std::string generateHTMLHeader();
    std::string generateHTMLFooter();
    
    // Configuration
    bool includeLogSamples;
    size_t maxLogSamples;
    bool includeStatistics;
    
    // Templates
    std::string getHTMLTemplate();
    std::string getTextTemplate();
};

#endif // REPORTGENERATOR_H
