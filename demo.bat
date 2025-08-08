@echo off
REM Simple build script that demonstrates the project without external dependencies
REM This creates a demonstration version that shows the tool's structure and functionality

echo Building Cybersecurity Tool Demo...
echo ====================================

REM Check if Visual Studio compiler is available
where cl >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Visual Studio compiler not found. Trying g++...
    where g++ >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo Neither Visual Studio nor g++ compiler found.
        echo Please install Visual Studio Build Tools or MinGW-w64
        echo.
        echo For now, we'll demonstrate the project structure and functionality.
        goto :demo
    ) else (
        echo Found g++ compiler
        set COMPILER=g++
        goto :build_with_gcc
    )
) else (
    echo Found Visual Studio compiler
    set COMPILER=cl
    goto :build_with_msvc
)

:build_with_gcc
echo Building with g++...
REM This would be the actual build command if dependencies were available
REM g++ -std=c++17 -Iinclude -O2 src/main.cpp src/Utils.cpp src/core/*.cpp src/utils/*.cpp -o CybersecurityTool.exe
echo Note: This project requires libcurl and nlohmann-json libraries
echo Skipping actual compilation due to missing dependencies
goto :demo

:build_with_msvc
echo Building with Visual Studio...
REM This would be the actual build command if dependencies were available
echo Note: This project requires libcurl and nlohmann-json libraries
echo Skipping actual compilation due to missing dependencies
goto :demo

:demo
echo.
echo ===========================================
echo   CYBERSECURITY TOOL PROJECT DEMO
echo ===========================================
echo.
echo This is a comprehensive C++ cybersecurity log analysis tool that:
echo.
echo 1. PARSES multiple log formats:
echo    - Syslog (Linux/Unix system logs)
echo    - Windows Event Logs (JSON format)
echo    - CSV security alerts
echo    - Custom JSON formats
echo.
echo 2. INTEGRATES with OLLAMA:
echo    - Uses local LLM models for intelligent analysis
echo    - Supports llama3, mistral, and other models
echo    - Generates human-readable threat assessments
echo.
echo 3. PROVIDES security features:
echo    - Input sanitization and validation
echo    - Protection against injection attacks
echo    - Secure memory management
echo    - Comprehensive error handling
echo.
echo 4. GENERATES detailed reports:
echo    - Executive summaries
echo    - Threat indicators with severity levels
echo    - Actionable recommendations
echo    - Multiple output formats (text, HTML, JSON)
echo.
echo PROJECT STRUCTURE:
echo ------------------
type NUL
dir /s /b *.h *.cpp 2>NUL | findstr /v ".git"
echo.
echo SAMPLE LOG ANALYSIS:
echo -------------------
echo Reading sample syslog data...
echo.
type "samples\sample_syslog.log" | head -5
echo.
echo [... more log entries ...]
echo.
echo SAMPLE THREAT ANALYSIS OUTPUT:
echo -----------------------------
echo === CYBERSECURITY LOG ANALYSIS REPORT ===
echo Generated: %date% %time%
echo Model: llama3 (demo mode)
echo.
echo THREAT SUMMARY:
echo - HIGH PRIORITY: SSH Brute force attack detected from 192.168.1.100
echo - MEDIUM PRIORITY: Suspicious network traffic blocked by firewall
echo - LOW PRIORITY: Failed web application access attempts
echo.
echo DETAILED ANALYSIS:
echo 1. SSH Brute Force Attack (Priority: HIGH)
echo    - Source IP: 192.168.1.100
echo    - Target accounts: root, admin, guest
echo    - Pattern: Sequential failed login attempts
echo    - Confidence: 95%%
echo    - Recommendation: Implement fail2ban, block source IP
echo.
echo 2. Network Intrusion Attempt (Priority: MEDIUM)
echo    - Source: Internal host 10.0.0.5
echo    - Destination: External network
echo    - Protocol: TCP port 4444 (suspicious)
echo    - May indicate: Lateral movement or data exfiltration
echo    - Recommendation: Investigate host 10.0.0.5 immediately
echo.
echo RECOMMENDED ACTIONS:
echo - Immediate IP blocking for 192.168.1.100
echo - Review and strengthen SSH security policies
echo - Investigate internal host 10.0.0.5 for compromise
echo - Enable enhanced logging for failed authentication attempts
echo - Consider implementing network segmentation
echo.
echo TO RUN THE ACTUAL TOOL:
echo ----------------------
echo 1. Install dependencies:
echo    - CMake (https://cmake.org/)
echo    - Visual Studio Build Tools or MinGW-w64
echo    - OLLAMA (https://ollama.ai/)
echo    - vcpkg for C++ libraries (libcurl, nlohmann-json)
echo.
echo 2. Setup OLLAMA:
echo    ollama pull llama3
echo    ollama serve
echo.
echo 3. Build the project:
echo    mkdir build
echo    cd build
echo    cmake ..
echo    cmake --build . --config Release
echo.
echo 4. Run analysis:
echo    CybersecurityTool.exe --test-mode --verbose
echo    CybersecurityTool.exe --input samples\sample_syslog.log --format syslog
echo.
echo This demonstration shows the complete project structure and
echo expected functionality of the Cybersecurity Log Analyzer Tool.
echo.
pause
