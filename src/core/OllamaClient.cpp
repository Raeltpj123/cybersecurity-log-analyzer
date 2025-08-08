#include "OllamaClient.h"
#include "../utils/Logger.h"
#include "../utils/SecurityUtils.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <regex>
#include <thread>
#include <chrono>

using json = nlohmann::json;

OllamaClient::OllamaClient(const std::string& host, int port, const std::string& model)
    : host_(host), port_(port), model_(model), retryCount_(3) {
}

OllamaClient::~OllamaClient() {
}

bool OllamaClient::testConnection() {
    try {
        Logger::getInstance().log(LogLevel::INFO, "Testing OLLAMA connection (simulated)...");
        // For now, simulate successful connection test
        Logger::getInstance().log(LogLevel::INFO, "OLLAMA connection test passed (simulated)");
        return true;
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Connection test failed: " + std::string(e.what()));
        return false;
    }
}

AnalysisReport OllamaClient::analyzeLogEntries(const std::vector<LogEntry>& entries, 
                                               const std::string& prompt,
                                               const std::string& model) {
    AnalysisReport report;
    report.timestamp = Utils::getCurrentTimestamp();
    report.model = model.empty() ? model_ : model;
    report.total_entries = entries.size();
    
    try {
        Logger::getInstance().log(LogLevel::INFO, "Analyzing " + std::to_string(entries.size()) + " log entries (simulated)");
        
        // Simulate analysis with basic threat detection
        for (const auto& entry : entries) {
            analyzeEntry(entry, report);
        }
        
        // Generate executive summary
        generateExecutiveSummary(report);
        
        Logger::getInstance().log(LogLevel::INFO, "Analysis completed. Found " + std::to_string(report.threats.size()) + " threats");
        
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR_LEVEL, "Analysis error: " + std::string(e.what()));
        report.error = "Analysis failed: " + std::string(e.what());
    }
    
    return report;
}

void OllamaClient::analyzeEntry(const LogEntry& entry, AnalysisReport& report) {
    // Basic pattern matching for common threats
    std::string message_lower = entry.message;
    std::transform(message_lower.begin(), message_lower.end(), message_lower.begin(), ::tolower);
    
    // SSH Brute Force Detection
    if (message_lower.find("failed password") != std::string::npos ||
        message_lower.find("authentication failure") != std::string::npos) {
        
        ThreatIndicator threat;
        threat.type = "brute_force";
        threat.severity = ThreatSeverity::HIGH;
        threat.confidence = 0.85f;
        threat.description = "SSH brute force attack detected";
        threat.source_ip = extractIP(entry.message);
        threat.indicators.push_back("Multiple failed authentication attempts");
        threat.recommendations.push_back("Block source IP immediately");
        threat.recommendations.push_back("Implement fail2ban protection");
        
        report.threats.push_back(threat);
    }
    
    // Malware Detection
    if (message_lower.find("malware") != std::string::npos ||
        message_lower.find("trojan") != std::string::npos ||
        message_lower.find("virus") != std::string::npos) {
        
        ThreatIndicator threat;
        threat.type = "malware_detected";
        threat.severity = ThreatSeverity::CRITICAL;
        threat.confidence = 0.95f;
        threat.description = "Malware detected on system";
        threat.source_ip = extractIP(entry.message);
        threat.indicators.push_back("Malicious file detected");
        threat.recommendations.push_back("Isolate affected system immediately");
        threat.recommendations.push_back("Run full system scan");
        
        report.threats.push_back(threat);
    }
    
    // Privilege Escalation
    if (message_lower.find("privilege") != std::string::npos &&
        message_lower.find("escalation") != std::string::npos) {
        
        ThreatIndicator threat;
        threat.type = "privilege_escalation";
        threat.severity = ThreatSeverity::CRITICAL;
        threat.confidence = 0.90f;
        threat.description = "Unauthorized privilege escalation detected";
        threat.source_ip = extractIP(entry.message);
        threat.indicators.push_back("Suspicious privilege elevation");
        threat.recommendations.push_back("Investigate user account immediately");
        threat.recommendations.push_back("Review authentication logs");
        
        report.threats.push_back(threat);
    }
    
    // Firewall/Network Events
    if (message_lower.find("blocked") != std::string::npos ||
        message_lower.find("drop") != std::string::npos ||
        message_lower.find("denied") != std::string::npos) {
        
        ThreatIndicator threat;
        threat.type = "blocked_connection";
        threat.severity = ThreatSeverity::MEDIUM;
        threat.confidence = 0.70f;
        threat.description = "Suspicious network activity blocked";
        threat.source_ip = extractIP(entry.message);
        threat.indicators.push_back("Firewall blocked suspicious connection");
        threat.recommendations.push_back("Monitor for additional attempts");
        threat.recommendations.push_back("Review network security policies");
        
        report.threats.push_back(threat);
    }
}

std::string OllamaClient::extractIP(const std::string& text) {
    std::regex ip_regex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
    std::smatch match;
    
    if (std::regex_search(text, match, ip_regex)) {
        return match.str();
    }
    
    return "N/A";
}

void OllamaClient::generateExecutiveSummary(AnalysisReport& report) {
    int critical_count = 0, high_count = 0, medium_count = 0, low_count = 0;
    
    for (const auto& threat : report.threats) {
        switch (threat.severity) {
            case ThreatSeverity::CRITICAL: critical_count++; break;
            case ThreatSeverity::HIGH: high_count++; break;
            case ThreatSeverity::MEDIUM: medium_count++; break;
            case ThreatSeverity::LOW: low_count++; break;
        }
    }
    
    report.critical_threats = critical_count;
    report.high_threats = high_count;
    report.medium_threats = medium_count;
    report.low_threats = low_count;
    
    std::ostringstream summary;
    summary << "Analysis completed at: " << report.timestamp << "\n";
    summary << "Total threats identified: " << report.threats.size() << "\n\n";
    summary << "Threat Breakdown:\n";
    summary << "  • Critical: " << critical_count << "\n";
    summary << "  • High: " << high_count << "\n";
    summary << "  • Medium: " << medium_count << "\n";
    summary << "  • Low: " << low_count << "\n\n";
    
    if (critical_count > 0) {
        summary << "⚠️  IMMEDIATE ACTION REQUIRED: Critical priority threats detected.\n";
    }
    
    report.executive_summary = summary.str();
}

std::vector<ThreatIndicator> OllamaClient::detectThreats(const std::vector<LogEntry>& entries, const std::string& custom_prompt) {
    AnalysisReport report = analyzeLogEntries(entries, custom_prompt, model_);
    return report.threats;
}

// Placeholder implementations for HTTP-related functions
OllamaResponse OllamaClient::generateCompletion(const OllamaRequest& request) {
    OllamaResponse response;
    response.success = true;
    response.content = "Simulated response - OLLAMA not available";
    return response;
}

std::string OllamaClient::makeHttpRequest(const std::string& url, const std::string& data) {
    return "Simulated HTTP response";
}

OllamaResponse OllamaClient::parseResponse(const std::string& response_str) {
    OllamaResponse response;
    response.success = true;
    response.content = response_str;
    return response;
}
