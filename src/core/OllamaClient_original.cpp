#include "OllamaClient.h"
#include "../utils/Logger.h"
#include "../utils/SecurityUtils.h"
#ifdef _WIN32
    #define NOMINMAX
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #undef ERROR  // Undefine ERROR macro that conflicts with LogLevel::ERROR
#endif
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <regex>
#include <thread>
#include <chrono>

using json = nlohmann::json;

// Callback function for libcurl to write response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

OllamaClient::OllamaClient(const std::string& baseUrl) : 
    baseUrl(baseUrl),
    defaultModel("llama3"),
    timeoutSeconds(Constants::OLLAMA_TIMEOUT_SECONDS),
    maxRetries(3),
    connected(false) {
    
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    Logger::getInstance().log(LogLevel::INFO, "OllamaClient initialized with URL: " + baseUrl);
}

OllamaClient::~OllamaClient() {
    curl_global_cleanup();
}

bool OllamaClient::testConnection() {
    try {
        std::string response = makeHttpRequest("/api/tags", "");
        
        if (!response.empty()) {
            // Try to parse the response to get available models
            json j = json::parse(response);
            if (j.contains("models")) {
                availableModels.clear();
                for (const auto& model : j["models"]) {
                    if (model.contains("name")) {
                        availableModels.push_back(model["name"]);
                    }
                }
                connected = true;
                Logger::getInstance().log(LogLevel::INFO, "Successfully connected to OLLAMA. Found " + 
                                        std::to_string(availableModels.size()) + " models.");
                return true;
            }
        }
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR, "Connection test failed: " + std::string(e.what()));
    }
    
    connected = false;
    return false;
}

std::vector<std::string> OllamaClient::getAvailableModels() {
    if (!connected) {
        testConnection();
    }
    return availableModels;
}

AnalysisReport OllamaClient::analyzeLogEntries(const std::vector<LogEntry>& entries, 
                                              const std::string& model, 
                                              const std::string& prompt) {
    AnalysisReport report;
    report.modelUsed = model;
    
    if (entries.empty()) {
        Logger::getInstance().log(LogLevel::WARNING, "No log entries to analyze");
        return report;
    }
    
    Logger::getInstance().log(LogLevel::INFO, "Starting analysis of " + std::to_string(entries.size()) + " log entries");
    
    try {
        // Build comprehensive prompt
        std::string fullPrompt = buildPrompt(entries, prompt);
        
        // Send to OLLAMA for analysis
        OllamaResponse response = sendPrompt(model, fullPrompt);
        
        if (!response.error.empty()) {
            Logger::getInstance().log(LogLevel::ERROR, "OLLAMA analysis failed: " + response.error);
            return report;
        }
        
        // Parse the response for threats and recommendations
        report.detailedAnalysis = response.response;
        report.threats = parseThreatResponse(response.response);
        
        // Generate summary
        report.summary = summarizeLogs(entries, model);
        
        // Generate recommendations based on detected threats
        if (!report.threats.empty()) {
            report.recommendations = generateRecommendations(report.threats, model);
        }
        
        // Calculate statistics
        report.statistics["total_entries"] = static_cast<int>(entries.size());
        report.statistics["critical_threats"] = 0;
        report.statistics["high_threats"] = 0;
        report.statistics["medium_threats"] = 0;
        report.statistics["low_threats"] = 0;
        
        for (const auto& threat : report.threats) {
            switch (threat.severity) {
                case ThreatLevel::CRITICAL:
                    report.statistics["critical_threats"]++;
                    break;
                case ThreatLevel::HIGH:
                    report.statistics["high_threats"]++;
                    break;
                case ThreatLevel::MEDIUM:
                    report.statistics["medium_threats"]++;
                    break;
                case ThreatLevel::LOW:
                    report.statistics["low_threats"]++;
                    break;
            }
        }
        
        Logger::getInstance().log(LogLevel::INFO, "Analysis completed. Found " + 
                                std::to_string(report.threats.size()) + " threats.");
        
    } catch (const std::exception& e) {
        Logger::getInstance().log(LogLevel::ERROR, "Analysis error: " + std::string(e.what()));
        report.detailedAnalysis = "Error during analysis: " + std::string(e.what());
    }
    
    return report;
}

OllamaResponse OllamaClient::sendPrompt(const std::string& model, const std::string& prompt) {
    OllamaRequest request;
    request.model = model;
    request.prompt = prompt;
    request.stream = false;
    
    return generateCompletion(request);
}

OllamaResponse OllamaClient::generateCompletion(const OllamaRequest& request) {
    OllamaResponse response;
    
    try {
        // Build JSON request
        json requestJson;
        requestJson["model"] = request.model;
        requestJson["prompt"] = request.prompt;
        requestJson["stream"] = request.stream;
        
        if (!request.options.empty()) {
            requestJson["options"] = request.options;
        }
        
        std::string jsonData = requestJson.dump();
        
        // Make HTTP request
        std::string rawResponse = makeHttpRequest("/api/generate", jsonData);
        
        if (!rawResponse.empty()) {
            response = parseResponse(rawResponse);
        } else {
            response.error = "Empty response from OLLAMA";
        }
        
    } catch (const std::exception& e) {
        response.error = "Request failed: " + std::string(e.what());
        Logger::getInstance().log(LogLevel::ERROR, response.error);
    }
    
    return response;
}

std::string OllamaClient::makeHttpRequest(const std::string& endpoint, const std::string& jsonData) {
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        std::string url = baseUrl + endpoint;
        
        // Set URL
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        
        // Set POST data if provided
        if (!jsonData.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonData.c_str());
        }
        
        // Set headers
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        // Set callback for response
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
        // Set timeout
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeoutSeconds);
        
        // Perform request with retries
        CURLcode res = CURLE_OK;
        for (int attempt = 0; attempt < maxRetries; ++attempt) {
            res = curl_easy_perform(curl);
            if (res == CURLE_OK) {
                break;
            }
            
            Logger::getInstance().log(LogLevel::WARNING, 
                "HTTP request attempt " + std::to_string(attempt + 1) + " failed: " + curl_easy_strerror(res));
            
            if (attempt < maxRetries - 1) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        // Check response code
        long responseCode;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
        
        if (responseCode != 200) {
            Logger::getInstance().log(LogLevel::ERROR, 
                "HTTP request failed with code: " + std::to_string(responseCode));
            response.clear();
        }
        
        // Cleanup
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    return response;
}

OllamaResponse OllamaClient::parseResponse(const std::string& rawResponse) {
    OllamaResponse response;
    
    try {
        json j = json::parse(rawResponse);
        
        response.response = j.value("response", "");
        response.done = j.value("done", false);
        
        if (j.contains("error")) {
            response.error = j["error"];
        }
        
        // Extract metadata if present
        if (j.contains("model")) {
            response.metadata["model"] = j["model"];
        }
        
        if (j.contains("created_at")) {
            response.metadata["created_at"] = j["created_at"];
        }
        
    } catch (const json::exception& e) {
        response.error = "Failed to parse response: " + std::string(e.what());
        Logger::getInstance().log(LogLevel::ERROR, response.error);
    }
    
    return response;
}

std::string OllamaClient::buildPrompt(const std::vector<LogEntry>& entries, const std::string& basePrompt) {
    std::ostringstream prompt;
    
    prompt << basePrompt << "\n\n";
    prompt << "Please analyze the following log entries and provide:\n";
    prompt << "1. A summary of potential threats and their severity levels\n";
    prompt << "2. Specific indicators of compromise (IoCs)\n";
    prompt << "3. Recommended actions for each threat\n";
    prompt << "4. Overall security assessment\n\n";
    
    prompt << "Log entries to analyze:\n";
    prompt << "========================\n";
    
    prompt << formatLogEntriesForPrompt(entries);
    
    prompt << "\n========================\n";
    prompt << "Please provide your analysis in a structured format with clear threat indicators,";
    prompt << " severity levels (LOW/MEDIUM/HIGH/CRITICAL), and actionable recommendations.";
    
    return prompt.str();
}

std::string OllamaClient::formatLogEntriesForPrompt(const std::vector<LogEntry>& entries) {
    std::ostringstream formatted;
    
    size_t maxEntries = std::min(entries.size(), static_cast<size_t>(50)); // Limit to avoid overwhelming the model
    
    for (size_t i = 0; i < maxEntries; ++i) {
        const LogEntry& entry = entries[i];
        
        formatted << "Entry " << (i + 1) << ":\n";
        formatted << "  Timestamp: " << Utils::getCurrentTimestamp() << "\n"; // Simplified
        formatted << "  Source: " << entry.source << "\n";
        formatted << "  Level: " << entry.level << "\n";
        formatted << "  Message: " << entry.message << "\n";
        
        if (!entry.metadata.empty()) {
            formatted << "  Metadata: ";
            for (const auto& meta : entry.metadata) {
                formatted << meta.first << "=" << meta.second << " ";
            }
            formatted << "\n";
        }
        
        formatted << "\n";
    }
    
    if (entries.size() > maxEntries) {
        formatted << "... and " << (entries.size() - maxEntries) << " more entries\n";
    }
    
    return formatted.str();
}

std::vector<ThreatIndicator> OllamaClient::parseThreatResponse(const std::string& response) {
    std::vector<ThreatIndicator> threats;
    
    // Use regex patterns to extract threat information from the response
    std::regex threatPattern(R"((HIGH|MEDIUM|LOW|CRITICAL)[:\s]+([^\n]+))");
    std::smatch matches;
    
    std::string::const_iterator searchStart(response.cbegin());
    while (std::regex_search(searchStart, response.cend(), matches, threatPattern)) {
        ThreatIndicator threat;
        
        std::string severityStr = matches[1].str();
        threat.severity = Utils::stringToSeverity(severityStr);
        threat.description = matches[2].str();
        threat.type = "log_analysis";
        threat.confidence = 0.8; // Default confidence
        
        // Extract IP addresses if present in the description
        std::regex ipPattern(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)");
        std::smatch ipMatch;
        if (std::regex_search(threat.description, ipMatch, ipPattern)) {
            threat.sourceIP = ipMatch[0].str();
        }
        
        threats.push_back(threat);
        searchStart = matches.suffix().first;
    }
    
    return threats;
}

std::string OllamaClient::summarizeLogs(const std::vector<LogEntry>& entries, const std::string& model) {
    std::string prompt = "Provide a concise summary of the following log entries, focusing on key security events and overall system activity:\n\n";
    prompt += formatLogEntriesForPrompt(entries);
    
    OllamaResponse response = sendPrompt(model, prompt);
    return response.error.empty() ? response.response : "Summary generation failed: " + response.error;
}

std::vector<std::string> OllamaClient::generateRecommendations(const std::vector<ThreatIndicator>& threats, const std::string& model) {
    std::vector<std::string> recommendations;
    
    if (threats.empty()) {
        return recommendations;
    }
    
    std::ostringstream prompt;
    prompt << "Based on the following detected threats, provide specific, actionable security recommendations:\n\n";
    
    for (size_t i = 0; i < threats.size(); ++i) {
        prompt << "Threat " << (i + 1) << ": " << Utils::severityToString(threats[i].severity) 
               << " - " << threats[i].description << "\n";
    }
    
    prompt << "\nPlease provide numbered recommendations for addressing these threats.";
    
    OllamaResponse response = sendPrompt(model, prompt.str());
    
    if (!response.error.empty()) {
        Logger::getInstance().log(LogLevel::WARNING, "Failed to generate recommendations: " + response.error);
        return recommendations;
    }
    
    // Parse numbered recommendations from response
    std::regex recPattern(R"(\d+\.\s*([^\n]+))");
    std::smatch matches;
    
    std::string::const_iterator searchStart(response.response.cbegin());
    while (std::regex_search(searchStart, response.response.cend(), matches, recPattern)) {
        recommendations.push_back(matches[1].str());
        searchStart = matches.suffix().first;
    }
    
    return recommendations;
}

std::vector<ThreatIndicator> OllamaClient::detectThreats(const std::vector<LogEntry>& entries, const std::string& model) {
    std::string prompt = "Analyze the following log entries specifically for security threats, attacks, and indicators of compromise. "
                        "Focus on identifying: brute force attacks, malware indicators, network intrusions, privilege escalation, "
                        "data exfiltration attempts, and suspicious user behavior.\n\n";
    
    prompt += formatLogEntriesForPrompt(entries);
    
    OllamaResponse response = sendPrompt(model, prompt);
    
    if (!response.error.empty()) {
        Logger::getInstance().log(LogLevel::ERROR, "Threat detection failed: " + response.error);
        return {};
    }
    
    return parseThreatResponse(response.response);
}

std::string OllamaClient::sanitizeForJson(const std::string& input) {
    return SecurityUtils::sanitizeInput(input);
}

bool OllamaClient::isModelAvailable(const std::string& model) {
    if (!connected) {
        testConnection();
    }
    
    return std::find(availableModels.begin(), availableModels.end(), model) != availableModels.end();
}
