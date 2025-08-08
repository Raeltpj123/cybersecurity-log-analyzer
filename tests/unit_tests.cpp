#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include "../src/utils/SecurityUtils.h"
#include "../src/utils/Logger.h"
#include "../src/core/LogParser.h"
#include "../include/Common.h"

class UnitTests {
private:
    int totalTests = 0;
    int passedTests = 0;
    
public:
    void runTest(const std::string& testName, bool result) {
        totalTests++;
        if (result) {
            passedTests++;
            std::cout << "[PASS] " << testName << std::endl;
        } else {
            std::cout << "[FAIL] " << testName << std::endl;
        }
    }
    
    void printResults() {
        std::cout << "\n" << std::string(50, '=') << std::endl;
        std::cout << "Test Results: " << passedTests << "/" << totalTests << " passed" << std::endl;
        if (passedTests == totalTests) {
            std::cout << "All tests passed!" << std::endl;
        } else {
            std::cout << (totalTests - passedTests) << " tests failed!" << std::endl;
        }
        std::cout << std::string(50, '=') << std::endl;
    }
};

void testSecurityUtils(UnitTests& tests) {
    std::cout << "\nTesting SecurityUtils..." << std::endl;
    
    // Test input sanitization
    tests.runTest("Sanitize normal input", 
        SecurityUtils::sanitizeInput("normal log entry") == "normal log entry");
    
    tests.runTest("Remove null bytes", 
        SecurityUtils::sanitizeInput("test\0null").find('\0') == std::string::npos);
    
    // Test path validation
    tests.runTest("Valid file path", 
        SecurityUtils::isValidFilePath("/var/log/syslog"));
    
    tests.runTest("Reject path traversal", 
        !SecurityUtils::isValidFilePath("../../../etc/passwd"));
    
    // Test URL validation
    tests.runTest("Valid HTTP URL", 
        SecurityUtils::isValidURL("http://localhost:11434"));
    
    tests.runTest("Valid HTTPS URL", 
        SecurityUtils::isValidURL("https://api.example.com:8080/v1"));
    
    tests.runTest("Reject invalid URL", 
        !SecurityUtils::isValidURL("not-a-url"));
    
    // Test injection detection
    tests.runTest("Detect SQL injection", 
        SecurityUtils::checkSQLInjection("'; DROP TABLE users; --"));
    
    tests.runTest("Detect XSS attempt", 
        SecurityUtils::checkXSS("<script>alert('xss')</script>"));
    
    tests.runTest("Detect command injection", 
        SecurityUtils::checkCommandInjection("test; rm -rf /"));
    
    // Test log entry validation
    tests.runTest("Valid log entry", 
        SecurityUtils::isValidLogEntry("Jan 15 10:23:45 server1 sshd[1234]: message"));
    
    tests.runTest("Reject oversized entry", 
        !SecurityUtils::isValidLogEntry(std::string(10000, 'a')));
}

void testUtilsFunctions(UnitTests& tests) {
    std::cout << "\nTesting Utils functions..." << std::endl;
    
    // Test severity conversions
    tests.runTest("Severity to string - HIGH", 
        Utils::severityToString(ThreatLevel::HIGH) == "HIGH");
    
    tests.runTest("String to severity - CRITICAL", 
        Utils::stringToSeverity("CRITICAL") == ThreatLevel::CRITICAL);
    
    tests.runTest("String to severity - case insensitive", 
        Utils::stringToSeverity("high") == ThreatLevel::HIGH);
    
    // Test format conversions
    tests.runTest("Format to string - SYSLOG", 
        Utils::formatToString(LogFormat::SYSLOG) == "syslog");
    
    tests.runTest("String to format - JSON", 
        Utils::stringToFormat("json") == LogFormat::JSON);
    
    tests.runTest("String to format - case insensitive", 
        Utils::stringToFormat("CSV") == LogFormat::CSV);
    
    // Test IP validation
    tests.runTest("Valid IP address", 
        Utils::isValidIP("192.168.1.100"));
    
    tests.runTest("Invalid IP address", 
        !Utils::isValidIP("256.256.256.256"));
    
    tests.runTest("Invalid IP format", 
        !Utils::isValidIP("not.an.ip.address"));
}

void testLogParser(UnitTests& tests) {
    std::cout << "\nTesting LogParser..." << std::endl;
    
    LogParser parser;
    
    // Test format detection
    tests.runTest("Detect syslog format", 
        parser.detectFormat("samples/sample_syslog.log") == LogFormat::SYSLOG);
    
    // Test sample data loading
    auto sampleEntries = parser.loadSampleData();
    tests.runTest("Load sample data", 
        !sampleEntries.empty());
    
    tests.runTest("Sample data has valid entries", 
        sampleEntries.size() >= 3);
    
    // Test log entry validation
    LogEntry validEntry;
    validEntry.source = "test";
    validEntry.message = "test message";
    validEntry.level = "INFO";
    
    tests.runTest("Validate correct log entry", 
        parser.validateLogEntry(validEntry));
    
    LogEntry invalidEntry;
    tests.runTest("Reject invalid log entry", 
        !parser.validateLogEntry(invalidEntry));
}

void testCommonStructs(UnitTests& tests) {
    std::cout << "\nTesting Common structures..." << std::endl;
    
    // Test Config structure
    Config config;
    tests.runTest("Config default format", 
        config.format == LogFormat::UNKNOWN);
    
    tests.runTest("Config default model", 
        config.ollamaModel == "llama3");
    
    tests.runTest("Config default URL", 
        config.ollamaUrl == "http://localhost:11434");
    
    // Test LogEntry structure
    LogEntry entry("test log line");
    tests.runTest("LogEntry raw storage", 
        entry.rawEntry == "test log line");
    
    // Test ThreatIndicator structure
    ThreatIndicator threat;
    tests.runTest("ThreatIndicator default severity", 
        threat.severity == ThreatLevel::LOW);
    
    tests.runTest("ThreatIndicator default confidence", 
        threat.confidence == 0.0);
    
    // Test AnalysisReport structure
    AnalysisReport report;
    tests.runTest("AnalysisReport timestamp set", 
        report.generatedAt > std::chrono::system_clock::time_point{});
}

void testErrorHandling(UnitTests& tests) {
    std::cout << "\nTesting Error Handling..." << std::endl;
    
    // Test with non-existent files
    LogParser parser;
    auto entries = parser.parseFile("non_existent_file.log");
    tests.runTest("Handle non-existent file", 
        entries.empty());
    
    // Test with invalid format
    auto unknownEntries = parser.parseFile("samples/sample_syslog.log", LogFormat::UNKNOWN);
    tests.runTest("Handle unknown format gracefully", 
        !unknownEntries.empty()); // Should auto-detect
    
    // Test security utils with edge cases
    tests.runTest("Handle empty input sanitization", 
        SecurityUtils::sanitizeInput("").empty());
    
    tests.runTest("Handle null path validation", 
        !SecurityUtils::isValidFilePath(""));
    
    tests.runTest("Handle empty URL validation", 
        !SecurityUtils::isValidURL(""));
}

int main() {
    std::cout << "Running Cybersecurity Tool Unit Tests" << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    
    UnitTests tests;
    
    try {
        // Initialize logger for testing
        Logger::getInstance().initialize("test.log", LogLevel::ERROR);
        
        // Run all test suites
        testSecurityUtils(tests);
        testUtilsFunctions(tests);
        testLogParser(tests);
        testCommonStructs(tests);
        testErrorHandling(tests);
        
        // Print final results
        tests.printResults();
        
        // Return appropriate exit code
        return (tests.passedTests == tests.totalTests) ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "Test execution failed: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown test execution error" << std::endl;
        return 1;
    }
}
