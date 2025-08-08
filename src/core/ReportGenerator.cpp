#include "ReportGenerator.h"
#include "../utils/Logger.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

ReportGenerator::ReportGenerator() :
    includeLogSamples(true),
    maxLogSamples(10),
    includeStatistics(true) {
}

ReportGenerator::~ReportGenerator() = default;

bool ReportGenerator::generateReport(const AnalysisReport& analysis, 
                                    const std::vector<LogEntry>& entries, 
                                    const std::string& outputFile) {
    try {
        std::ofstream file(outputFile);
        if (!file.is_open()) {
            Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Cannot create output file: " + outputFile);
            return false;
        }
        
        // Generate text report
        file << generateHeader();
        file << generateExecutiveSummary(analysis);
        file << "\n" << generateThreatDetails(analysis.threats);
        file << "\n" << generateRecommendations(analysis.recommendations);
        
        if (includeStatistics) {
            file << "\n" << generateStatistics(analysis.statistics);
        }
        
        if (includeLogSamples) {
            file << "\n" << generateLogSample(entries, maxLogSamples);
        }
        
        file << "\n" << generateFooter();
        file << "\nDetailed Analysis:\n";
        file << "==================\n";
        file << analysis.detailedAnalysis << "\n";
        
        file.close();
        
        Logger::getInstance().log(LogLevel::INFO, "Report generated successfully: " + outputFile);
        return true;
        
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Report generation failed: " + std::string(e.what()));
        return false;
    }
}

bool ReportGenerator::generateHTMLReport(const AnalysisReport& analysis, 
                                        const std::vector<LogEntry>& entries, 
                                        const std::string& outputFile) {
    try {
        std::ofstream file(outputFile);
        if (!file.is_open()) {
            Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Cannot create HTML output file: " + outputFile);
            return false;
        }
        
        file << generateHTMLHeader();
        
        // Executive Summary
        file << "<section class='summary'>\n";
        file << "<h2>Executive Summary</h2>\n";
        file << "<p>" << escapeHTML(generateExecutiveSummary(analysis)) << "</p>\n";
        file << "</section>\n\n";
        
        // Threat Details
        file << "<section class='threats'>\n";
        file << "<h2>Threat Analysis</h2>\n";
        for (const auto& threat : analysis.threats) {
            file << "<div class='threat threat-" << formatThreatLevel(threat.severity) << "'>\n";
            file << "<h3>" << formatThreatLevel(threat.severity) << " Priority</h3>\n";
            file << "<p><strong>Type:</strong> " << escapeHTML(threat.type) << "</p>\n";
            file << "<p><strong>Description:</strong> " << escapeHTML(threat.description) << "</p>\n";
            if (!threat.sourceIP.empty()) {
                file << "<p><strong>Source IP:</strong> " << escapeHTML(threat.sourceIP) << "</p>\n";
            }
            file << "<p><strong>Confidence:</strong> " << std::fixed << std::setprecision(1) 
                 << (threat.confidence * 100) << "%</p>\n";
            file << "</div>\n\n";
        }
        file << "</section>\n\n";
        
        // Recommendations
        if (!analysis.recommendations.empty()) {
            file << "<section class='recommendations'>\n";
            file << "<h2>Recommendations</h2>\n";
            file << "<ol>\n";
            for (const auto& rec : analysis.recommendations) {
                file << "<li>" << escapeHTML(rec) << "</li>\n";
            }
            file << "</ol>\n";
            file << "</section>\n\n";
        }
        
        // Statistics
        if (includeStatistics && !analysis.statistics.empty()) {
            file << "<section class='statistics'>\n";
            file << "<h2>Statistics</h2>\n";
            file << "<table>\n";
            for (const auto& stat : analysis.statistics) {
                file << "<tr><td>" << escapeHTML(stat.first) << "</td><td>" << stat.second << "</td></tr>\n";
            }
            file << "</table>\n";
            file << "</section>\n\n";
        }
        
        file << generateHTMLFooter();
        file.close();
        
        Logger::getInstance().log(LogLevel::INFO, "HTML report generated successfully: " + outputFile);
        return true;
        
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, "HTML report generation failed: " + std::string(e.what()));
        return false;
    }
}

bool ReportGenerator::generateJSONReport(const AnalysisReport& analysis, 
                                        const std::vector<LogEntry>& entries, 
                                        const std::string& outputFile) {
    try {
        json reportJson;
        
        // Metadata
        reportJson["metadata"]["generated_at"] = formatTimestamp(analysis.generatedAt);
        reportJson["metadata"]["model_used"] = analysis.modelUsed;
        reportJson["metadata"]["version"] = std::to_string(VERSION_MAJOR) + "." + 
                                           std::to_string(VERSION_MINOR) + "." + 
                                           std::to_string(VERSION_PATCH);
        
        // Summary
        reportJson["summary"] = analysis.summary;
        reportJson["detailed_analysis"] = analysis.detailedAnalysis;
        
        // Threats
        json threatsArray = json::array();
        for (const auto& threat : analysis.threats) {
            json threatJson;
            threatJson["severity"] = Utils::severityToString(threat.severity);
            threatJson["type"] = threat.type;
            threatJson["description"] = threat.description;
            threatJson["source_ip"] = threat.sourceIP;
            threatJson["target_ip"] = threat.targetIP;
            threatJson["confidence"] = threat.confidence;
            threatJson["indicators"] = threat.indicators;
            threatJson["recommendations"] = threat.recommendations;
            threatsArray.push_back(threatJson);
        }
        reportJson["threats"] = threatsArray;
        
        // Recommendations
        reportJson["recommendations"] = analysis.recommendations;
        
        // Statistics
        reportJson["statistics"] = analysis.statistics;
        
        // Log samples (if enabled)
        if (includeLogSamples) {
            json logSamples = json::array();
            size_t maxSamples = std::min(entries.size(), maxLogSamples);
            for (size_t i = 0; i < maxSamples; ++i) {
                json logEntry;
                logEntry["timestamp"] = formatTimestamp(entries[i].timestamp);
                logEntry["source"] = entries[i].source;
                logEntry["level"] = entries[i].level;
                logEntry["message"] = entries[i].message;
                logEntry["metadata"] = entries[i].metadata;
                logSamples.push_back(logEntry);
            }
            reportJson["log_samples"] = logSamples;
        }
        
        // Write to file
        std::ofstream file(outputFile);
        if (!file.is_open()) {
            Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Cannot create JSON output file: " + outputFile);
            return false;
        }
        
        file << reportJson.dump(4) << std::endl;
        file.close();
        
        Logger::getInstance().log(LogLevel::INFO, "JSON report generated successfully: " + outputFile);
        return true;
        
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, "JSON report generation failed: " + std::string(e.what()));
        return false;
    }
}

std::string ReportGenerator::generateExecutiveSummary(const AnalysisReport& analysis) {
    std::ostringstream summary;
    
    summary << "EXECUTIVE SUMMARY\n";
    summary << "=================\n\n";
    
    // Threat overview
    size_t totalThreats = analysis.threats.size();
    size_t criticalThreats = 0;
    size_t highThreats = 0;
    size_t mediumThreats = 0;
    size_t lowThreats = 0;
    
    for (const auto& threat : analysis.threats) {
        switch (threat.severity) {
            case ThreatLevel::CRITICAL: criticalThreats++; break;
            case ThreatLevel::HIGH: highThreats++; break;
            case ThreatLevel::MEDIUM: mediumThreats++; break;
            case ThreatLevel::LOW: lowThreats++; break;
        }
    }
    
    summary << "Analysis completed at: " << formatTimestamp(analysis.generatedAt) << "\n";
    summary << "Model used: " << analysis.modelUsed << "\n";
    summary << "Total threats identified: " << totalThreats << "\n\n";
    
    if (totalThreats > 0) {
        summary << "Threat Breakdown:\n";
        if (criticalThreats > 0) summary << "  • Critical: " << criticalThreats << "\n";
        if (highThreats > 0) summary << "  • High: " << highThreats << "\n";
        if (mediumThreats > 0) summary << "  • Medium: " << mediumThreats << "\n";
        if (lowThreats > 0) summary << "  • Low: " << lowThreats << "\n";
        summary << "\n";
        
        if (criticalThreats > 0 || highThreats > 0) {
            summary << "⚠️  IMMEDIATE ACTION REQUIRED: High or critical priority threats detected.\n\n";
        }
    } else {
        summary << "✅ No significant security threats detected in the analyzed logs.\n\n";
    }
    
    // Add summary if available
    if (!analysis.summary.empty() && analysis.summary != analysis.detailedAnalysis) {
        summary << "Summary:\n" << analysis.summary << "\n\n";
    }
    
    return summary.str();
}

std::string ReportGenerator::generateThreatDetails(const std::vector<ThreatIndicator>& threats) {
    std::ostringstream details;
    
    details << "THREAT ANALYSIS\n";
    details << "===============\n\n";
    
    if (threats.empty()) {
        details << "No specific threats identified.\n";
        return details.str();
    }
    
    // Sort threats by severity (critical first)
    auto sortedThreats = threats;
    std::sort(sortedThreats.begin(), sortedThreats.end(), 
              [](const ThreatIndicator& a, const ThreatIndicator& b) {
                  return static_cast<int>(a.severity) > static_cast<int>(b.severity);
              });
    
    for (size_t i = 0; i < sortedThreats.size(); ++i) {
        const auto& threat = sortedThreats[i];
        
        details << "Threat " << (i + 1) << ": " << formatThreatLevel(threat.severity) << " Priority\n";
        details << "Type: " << threat.type << "\n";
        details << "Description: " << threat.description << "\n";
        
        if (!threat.sourceIP.empty()) {
            details << "Source IP: " << threat.sourceIP << "\n";
        }
        
        if (!threat.targetIP.empty()) {
            details << "Target IP: " << threat.targetIP << "\n";
        }
        
        details << "Confidence: " << std::fixed << std::setprecision(1) 
                << (threat.confidence * 100) << "%\n";
        
        if (!threat.indicators.empty()) {
            details << "Indicators:\n";
            for (const auto& indicator : threat.indicators) {
                details << "  • " << indicator << "\n";
            }
        }
        
        if (!threat.recommendations.empty()) {
            details << "Recommendations:\n";
            for (const auto& rec : threat.recommendations) {
                details << "  • " << rec << "\n";
            }
        }
        
        details << "\n" << std::string(50, '-') << "\n\n";
    }
    
    return details.str();
}

std::string ReportGenerator::generateRecommendations(const std::vector<std::string>& recommendations) {
    std::ostringstream recs;
    
    recs << "RECOMMENDATIONS\n";
    recs << "===============\n\n";
    
    if (recommendations.empty()) {
        recs << "No specific recommendations generated.\n";
        return recs.str();
    }
    
    for (size_t i = 0; i < recommendations.size(); ++i) {
        recs << (i + 1) << ". " << recommendations[i] << "\n\n";
    }
    
    return recs.str();
}

std::string ReportGenerator::generateStatistics(const std::map<std::string, int>& stats) {
    std::ostringstream statistics;
    
    statistics << "STATISTICS\n";
    statistics << "==========\n\n";
    
    for (const auto& stat : stats) {
        statistics << std::left << std::setw(25) << (stat.first + ":") 
                  << stat.second << "\n";
    }
    
    statistics << "\n";
    return statistics.str();
}

std::string ReportGenerator::generateLogSample(const std::vector<LogEntry>& entries, size_t maxEntries) {
    std::ostringstream sample;
    
    sample << "LOG SAMPLES\n";
    sample << "===========\n\n";
    
    size_t sampleSize = std::min(entries.size(), maxEntries);
    
    for (size_t i = 0; i < sampleSize; ++i) {
        const auto& entry = entries[i];
        
        sample << "Entry " << (i + 1) << ":\n";
        sample << "  Timestamp: " << formatTimestamp(entry.timestamp) << "\n";
        sample << "  Source: " << entry.source << "\n";
        sample << "  Level: " << entry.level << "\n";
        sample << "  Message: " << entry.message << "\n";
        
        if (!entry.metadata.empty()) {
            sample << "  Metadata: ";
            for (const auto& meta : entry.metadata) {
                sample << meta.first << "=" << meta.second << " ";
            }
            sample << "\n";
        }
        
        sample << "\n";
    }
    
    if (entries.size() > maxEntries) {
        sample << "... and " << (entries.size() - maxEntries) << " more entries\n";
    }
    
    return sample.str();
}

std::string ReportGenerator::generateHeader() {
    std::ostringstream header;
    
    header << "=====================================\n";
    header << "  CYBERSECURITY ANALYSIS REPORT\n";
    header << "=====================================\n";
    header << "Generated by: Cybersecurity Tool v" 
           << VERSION_MAJOR << "." << VERSION_MINOR << "." << VERSION_PATCH << "\n";
    header << "Report Date: " << Utils::getCurrentTimestamp() << "\n";
    header << "=====================================\n\n";
    
    return header.str();
}

std::string ReportGenerator::generateFooter() {
    std::ostringstream footer;
    
    footer << "\n=====================================\n";
    footer << "End of Report\n";
    footer << "=====================================\n";
    footer << "This report was automatically generated\n";
    footer << "by the CISA Cybersecurity Analysis Tool.\n";
    footer << "For questions, contact your SOC team.\n";
    
    return footer.str();
}

std::string ReportGenerator::generateHTMLHeader() {
    return R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cybersecurity Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .summary { background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .threat { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 5px solid; }
        .threat-critical { background: #ffebee; border-color: #f44336; }
        .threat-high { background: #fff3e0; border-color: #ff9800; }
        .threat-medium { background: #e8f5e8; border-color: #4caf50; }
        .threat-low { background: #e3f2fd; border-color: #2196f3; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .footer { background: #34495e; color: white; padding: 15px; text-align: center; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Cybersecurity Analysis Report</h1>
        <p>Generated by CISA Cybersecurity Tool</p>
    </div>
)";
}

std::string ReportGenerator::generateHTMLFooter() {
    return R"(
    <div class="footer">
        <p>End of Report - Generated by CISA Cybersecurity Analysis Tool</p>
        <p>For questions, contact your SOC team</p>
    </div>
</body>
</html>
)";
}

std::string ReportGenerator::formatTimestamp(const std::chrono::system_clock::time_point& timestamp) {
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string ReportGenerator::formatThreatLevel(ThreatLevel level) {
    return Utils::severityToString(level);
}

std::string ReportGenerator::escapeHTML(const std::string& input) {
    std::string output = input;
    
    // Replace HTML special characters
    size_t pos = 0;
    while ((pos = output.find("&", pos)) != std::string::npos) {
        output.replace(pos, 1, "&amp;");
        pos += 5;
    }
    
    pos = 0;
    while ((pos = output.find("<", pos)) != std::string::npos) {
        output.replace(pos, 1, "&lt;");
        pos += 4;
    }
    
    pos = 0;
    while ((pos = output.find(">", pos)) != std::string::npos) {
        output.replace(pos, 1, "&gt;");
        pos += 4;
    }
    
    pos = 0;
    while ((pos = output.find("\"", pos)) != std::string::npos) {
        output.replace(pos, 1, "&quot;");
        pos += 6;
    }
    
    return output;
}

std::string ReportGenerator::escapeJSON(const std::string& input) {
    // Use nlohmann::json for proper JSON escaping
    json j = input;
    return j.dump();
}
