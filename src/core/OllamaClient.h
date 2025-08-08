#ifndef OLLAMACLIENT_H
#define OLLAMACLIENT_H

#include "../include/Common.h"
#include <vector>
#include <string>
#include <memory>

class OllamaClient {
public:
    explicit OllamaClient(const std::string& baseUrl = "http://localhost:11434");
    ~OllamaClient();
    
    // Connection and health check
    bool testConnection();
    std::vector<std::string> getAvailableModels();
    
    // Main analysis functions
    AnalysisReport analyzeLogEntries(const std::vector<LogEntry>& entries, 
                                   const std::string& model, 
                                   const std::string& prompt);
    
    // Individual API calls
    OllamaResponse sendPrompt(const std::string& model, const std::string& prompt);
    OllamaResponse generateCompletion(const OllamaRequest& request);
    
    // Specialized analysis functions
    std::vector<ThreatIndicator> detectThreats(const std::vector<LogEntry>& entries, const std::string& model);
    std::string summarizeLogs(const std::vector<LogEntry>& entries, const std::string& model);
    std::vector<std::string> generateRecommendations(const std::vector<ThreatIndicator>& threats, const std::string& model);
    
    // Configuration
    void setModel(const std::string& model) { defaultModel = model; }
    void setTimeout(int seconds) { timeoutSeconds = seconds; }
    void setMaxRetries(int retries) { maxRetries = retries; }
    
private:
    // HTTP client functionality
    std::string makeHttpRequest(const std::string& endpoint, const std::string& jsonData);
    std::string buildPrompt(const std::vector<LogEntry>& entries, const std::string& basePrompt);
    
    // Response parsing
    OllamaResponse parseResponse(const std::string& rawResponse);
    std::vector<ThreatIndicator> parseThreatResponse(const std::string& response);
    
    // Utility functions
    std::string formatLogEntriesForPrompt(const std::vector<LogEntry>& entries);
    std::string sanitizeForJson(const std::string& input);
    bool isModelAvailable(const std::string& model);
    
    // Configuration
    std::string baseUrl;
    std::string defaultModel;
    int timeoutSeconds;
    int maxRetries;
    
    // Internal state
    bool connected;
    std::vector<std::string> availableModels;
};

#endif // OLLAMACLIENT_H
