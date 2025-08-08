/**
 * @file main.cpp
 * @brief Main entry point for the Cybersecurity Log Analyzer Tool
 * 
 * This tool leverages OLLAMA (local LLM) to parse, analyze, and summarize 
 * various log formats for cybersecurity threat detection and incident triage.
 * 
 * Features:
 * - Multi-format log parsing (syslog, Windows Event, JSON, CSV)
 * - AI-powered threat analysis using OLLAMA
 * - Comprehensive security validation and input sanitization
 * - Cross-platform compatibility (Windows, Linux, macOS)
 * - Detailed reporting with threat prioritization
 * 
 * @author Cybersecurity Tool Development Team
 * @date August 2025
 * @version 1.0.0
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "Common.h"
#include "core/LogParser.h"
#include "core/OllamaClient.h"
#include "core/ReportGenerator.h"
#include "utils/Logger.h"
#include "utils/SecurityUtils.h"

/**
 * @brief Print usage information and command-line options
 * @param programName The name of the program executable
 */
void printUsage(const char* programName) {
    std::cout << "Cybersecurity Log Analyzer Tool v" 
              << VERSION_MAJOR << "." << VERSION_MINOR << "." << VERSION_PATCH << std::endl;
    std::cout << "AI-powered log analysis for SOC analysts and cybersecurity professionals" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage: " << programName << " [OPTIONS]" << std::endl;
    std::cout << std::endl;
    std::cout << "Required:" << std::endl;
    std::cout << "  -i, --input FILE      Input log file to analyze" << std::endl;
    std::cout << std::endl;
    std::cout << "Optional:" << std::endl;
    std::cout << "  -o, --output FILE     Output report file (default: cybersec_analysis_report.txt)" << std::endl;
    std::cout << "  -f, --format FORMAT   Log format: syslog, windows, json, csv (auto-detect if not specified)" << std::endl;
    std::cout << "  -m, --model MODEL     OLLAMA model to use (default: llama3)" << std::endl;
    std::cout << "  -u, --url URL         OLLAMA server URL (default: http://localhost:11434)" << std::endl;
    std::cout << "  -p, --prompt TEXT     Custom analysis prompt for specialized threat detection" << std::endl;
    std::cout << "  -t, --test-mode       Run in test mode with sample data (no OLLAMA required)" << std::endl;
    std::cout << "  -v, --verbose         Enable verbose logging for debugging" << std::endl;
    std::cout << "  -h, --help           Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << programName << " -i /var/log/syslog -f syslog -o report.txt" << std::endl;
    std::cout << "  " << programName << " -i alerts.json -m mistral -p \"Focus on APT indicators\"" << std::endl;
    std::cout << "  " << programName << " -t -v  # Test mode with verbose output" << std::endl;
    std::cout << std::endl;
    std::cout << "For more information, visit: https://github.com/cybersecurity-tool" << std::endl;
}

/**
 * @brief Parse and validate command-line arguments
 * 
 * Processes command-line arguments with comprehensive security validation.
 * All user inputs are sanitized to prevent injection attacks and path traversal.
 * 
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return Config structure containing validated configuration options
 */
Config parseArguments(int argc, char* argv[]) {
    Config config;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            exit(0);
        }
        else if (arg == "-t" || arg == "--test-mode") {
            config.testMode = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        }
        else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
            config.inputFile = SecurityUtils::sanitizeFilePath(argv[++i]);
        }
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            config.outputFile = SecurityUtils::sanitizeFilePath(argv[++i]);
        }
        else if ((arg == "-f" || arg == "--format") && i + 1 < argc) {
            config.format = Utils::stringToFormat(argv[++i]);
        }
        else if ((arg == "-m" || arg == "--model") && i + 1 < argc) {
            config.ollamaModel = SecurityUtils::sanitizeInput(argv[++i]);
        }
        else if ((arg == "-u" || arg == "--url") && i + 1 < argc) {
            config.ollamaUrl = SecurityUtils::sanitizeURL(argv[++i]);
        }
        else if ((arg == "-p" || arg == "--prompt") && i + 1 < argc) {
            config.customPrompt = SecurityUtils::sanitizeInput(argv[++i]);
        }
        else {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            exit(1);
        }
    }
    
    if (config.outputFile.empty()) {
        config.outputFile = Constants::DEFAULT_OUTPUT_FILE;
    }
    
    return config;
}

/**
 * @brief Validate configuration parameters
 * 
 * Performs comprehensive validation of configuration settings including:
 * - Required parameter presence
 * - File accessibility and permissions
 * - Path security validation
 * 
 * @param config Configuration structure to validate
 * @return true if configuration is valid, false otherwise
 */
bool validateConfig(const Config& config) {
    if (!config.testMode && config.inputFile.empty()) {
        std::cerr << "Error: Input file is required (use -i or --input)" << std::endl;
        return false;
    }
    
    if (!config.testMode && !std::ifstream(config.inputFile)) {
        std::cerr << "Error: Cannot open input file: " << config.inputFile << std::endl;
        return false;
    }
    
    return true;
}

/**
 * @brief Main entry point for the Cybersecurity Log Analyzer Tool
 * 
 * This function orchestrates the entire log analysis workflow:
 * 1. Parse and validate command-line arguments
 * 2. Initialize logging system and components
 * 3. Test OLLAMA connection (if not in test mode)
 * 4. Parse log files or load sample data
 * 5. Perform AI-powered threat analysis
 * 6. Generate comprehensive security reports
 * 
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on success, 1 on error
 */
int main(int argc, char* argv[]) {
    try {
        // Parse command line arguments with security validation
        Config config = parseArguments(argc, argv);
        
        // Validate configuration before proceeding
        if (!validateConfig(config)) {
            return 1;
        }
        
        // Initialize logging system with appropriate verbosity level
        Logger::getInstance().initialize(Constants::LOG_FILE, config.verbose ? LogLevel::DEBUG : LogLevel::INFO);
        Logger::getInstance().log(LogLevel::INFO, "Cybersecurity Tool started");
        
        // Test OLLAMA connection first (skip in test mode)
        OllamaClient ollamaClient(config.ollamaUrl);
        if (!config.testMode && !ollamaClient.testConnection()) {
            std::cerr << "Error: Cannot connect to OLLAMA server at " << config.ollamaUrl << std::endl;
            std::cerr << "Please ensure OLLAMA is running and the URL is correct." << std::endl;
            std::cerr << "Alternatively, use --test-mode to run without OLLAMA." << std::endl;
            return 1;
        }
        
        if (!config.testMode) {
            std::cout << "Connected to OLLAMA server successfully." << std::endl;
        }
        
        // Initialize core components
        LogParser logParser;
        ReportGenerator reportGen;
        
        // Parse logs or load sample data
        std::cout << "Parsing log file: " << config.inputFile << std::endl;
        std::vector<LogEntry> entries;
        
        if (config.testMode) {
            // Load sample data for testing without external dependencies
            entries = logParser.loadSampleData();
            std::cout << "Loaded " << entries.size() << " sample log entries for testing." << std::endl;
        } else {
            // Parse actual log file with format detection
            entries = logParser.parseFile(config.inputFile, config.format);
            std::cout << "Parsed " << entries.size() << " log entries." << std::endl;
        }
        
        if (entries.empty()) {
            std::cerr << "Warning: No log entries found to analyze." << std::endl;
            return 0;
        }
        
        // Prepare analysis prompt with cybersecurity focus
        std::string prompt = config.customPrompt;
        if (prompt.empty()) {
            prompt = "Analyze the following cybersecurity log entries for threats, anomalies, and security incidents. "
                    "Identify any suspicious patterns, potential attacks, or indicators of compromise. "
                    "Classify threats by severity (CRITICAL, HIGH, MEDIUM, LOW) and provide specific "
                    "remediation recommendations. Focus on APT indicators, brute force attacks, "
                    "privilege escalation attempts, and data exfiltration patterns.";
        }
        
        // Analyze logs with OLLAMA (or simulate in test mode)
        std::cout << "Analyzing logs with OLLAMA model: " << config.ollamaModel << std::endl;
        AnalysisReport report;
        
        if (config.testMode) {
            // Generate simulated analysis report for testing
            report = ollamaClient.analyzeLogEntries(entries, config.ollamaModel, prompt);
        } else {
            // Perform actual AI analysis
            report = ollamaClient.analyzeLogEntries(entries, config.ollamaModel, prompt);
        }
        
        // Generate and save comprehensive security report
        std::cout << "Generating analysis report..." << std::endl;
        bool success = reportGen.generateReport(report, entries, config.outputFile);
        
        if (success) {
            std::cout << "Analysis complete! Report saved to: " << config.outputFile << std::endl;
            
            // Print threat summary to console for immediate visibility
            std::cout << std::endl << "=== THREAT SUMMARY ===" << std::endl;
            for (const auto& threat : report.threats) {
                std::cout << "- " << Utils::severityToString(threat.severity) 
                         << ": " << threat.description << std::endl;
            }
            
            if (report.threats.empty()) {
                std::cout << "No significant threats detected in the analyzed logs." << std::endl;
            } else {
                std::cout << std::endl << "Total threats identified: " << report.threats.size() << std::endl;
                std::cout << "Review the full report for detailed analysis and recommendations." << std::endl;
            }
        } else {
            std::cerr << "Error: Failed to generate report." << std::endl;
            return 1;
        }
        
        Logger::getInstance().log(LogLevel::INFO, "Cybersecurity Tool completed successfully");
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        Logger::getInstance().log(LogLevel::CRITICAL, "Fatal error: " + std::string(e.what()));
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred." << std::endl;
        Logger::getInstance().log(LogLevel::CRITICAL, "Unknown fatal error occurred");
        return 1;
    }
    
    return 0;
}
