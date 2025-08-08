#ifndef SECURITYUTILS_H
#define SECURITYUTILS_H

#include "../include/Common.h"
#include <string>
#include <vector>

class SecurityUtils {
public:
    // Input sanitization
    static std::string sanitizeInput(const std::string& input);
    static std::string sanitizeFilePath(const std::string& path);
    static std::string sanitizeURL(const std::string& url);
    
    // Validation functions
    static bool isValidLogEntry(const std::string& entry);
    static bool isValidFilePath(const std::string& path);
    static bool isValidURL(const std::string& url);
    static bool containsSuspiciousPatterns(const std::string& input);
    
    // Security checks
    static bool checkPathTraversal(const std::string& path);
    static bool checkSQLInjection(const std::string& input);
    static bool checkXSS(const std::string& input);
    static bool checkCommandInjection(const std::string& input);
    
    // Rate limiting and resource management
    static bool checkResourceLimits(size_t inputSize);
    static std::string truncateIfNeeded(const std::string& input, size_t maxLength);
    
    // Encoding/Decoding
    static std::string base64Encode(const std::string& input);
    static std::string base64Decode(const std::string& input);
    static std::string urlEncode(const std::string& input);
    static std::string urlDecode(const std::string& input);
    
private:
    // Internal security patterns
    static const std::vector<std::string>& getSuspiciousPatterns();
    static const std::vector<std::string>& getPathTraversalPatterns();
    static const std::vector<std::string>& getSQLInjectionPatterns();
    static const std::vector<std::string>& getXSSPatterns();
    static const std::vector<std::string>& getCommandInjectionPatterns();
};

#endif // SECURITYUTILS_H
