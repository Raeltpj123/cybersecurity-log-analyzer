# Cybersecurity Log Analyzer Tool

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)]()
[![CISA Compliant](https://img.shields.io/badge/CISA-compliant-green)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

## Project Overview
A production-ready cybersecurity analyst utility that leverages OLLAMA (local LLM) to parse, analyze, and summarize various log formats. Designed for SOC analysts, this tool assists in threat detection, incident triage, and alert prioritization while maintaining security best practices and CISA compliance standards.

**Current Status**: ✅ Production Ready - All core features implemented and tested

## Quick Start (Windows PowerShell)
```powershell
# 1. Build the project
.\build.bat

# 2. Run test mode (no external dependencies)
.\build\bin\Release\CybersecurityTool.exe --test-mode --verbose

# 3. Run unit tests
.\build\bin\Release\unit_tests.exe

# 4. Test with sample data
.\build\bin\Release\CybersecurityTool.exe --input samples\sample_syslog.log --format syslog --output report.txt
```

## Features
- **Multi-format Log Parsing**: Supports syslog, Windows Event logs (JSON), and CSV alert formats with auto-detection
- **OLLAMA Integration**: Leverages local LLM models (llama3, mistral) for intelligent threat analysis
- **Threat Detection**: Advanced pattern recognition for APT indicators, brute force attacks, and anomalous behavior  
- **Report Generation**: Creates detailed summaries in text, HTML, and JSON formats with executive summaries
- **Security-First Design**: Input sanitization, injection protection, memory safety, and comprehensive error handling
- **Cross-Platform Support**: Windows, Linux, and macOS compatibility with CMake build system
- **Test Mode**: Complete functionality testing without external dependencies
- **Modular Architecture**: Clean, maintainable C++17 codebase following SOLID principles

## Architecture
```
├── src/
│   ├── main.cpp              # Entry point and CLI interface
│   ├── Utils.cpp             # General utility functions
│   ├── core/
│   │   ├── LogParser.h/cpp   # Multi-format log parsing logic
│   │   ├── OllamaClient.h/cpp # OLLAMA API integration & HTTP client
│   │   └── ReportGenerator.h/cpp # Multi-format report generation
│   └── utils/
│       ├── SecurityUtils.h/cpp   # Input sanitization & validation
│       └── Logger.h/cpp          # Thread-safe logging system
├── include/
│   └── Common.h              # Common definitions, structs & enums
├── samples/
│   ├── sample_syslog.log     # Sample Unix/Linux syslog data
│   ├── sample_windows.json   # Sample Windows Event log JSON
│   └── sample_alerts.csv     # Sample security alert CSV data
├── tests/
│   └── unit_tests.cpp        # Comprehensive unit test suite
├── docs/
│   ├── TEAM_ROLES.md         # Team member contributions
│   └── FINAL_REPORT.md       # Project completion report
├── .vscode/                  # VS Code configuration files
├── build.bat                 # Windows build script
├── build.sh                  # Linux/macOS build script
├── demo.bat                  # Windows demo runner
├── test_runner.bat           # Project validation script
├── CMakeLists.txt            # Cross-platform build configuration
├── INSTALL.md                # Detailed installation instructions
└── PROJECT_DEMO.txt          # Demonstration output sample
```

## Dependencies
- **C++17** or later (MSVC 2019+, GCC 8+, Clang 7+)
- **CMake** 3.15 or later for cross-platform building
- **libcurl** for HTTP requests to OLLAMA API
- **nlohmann/json** for JSON parsing (header-only library)
- **OLLAMA** with a compatible model (llama3, mistral, codellama)

### Optional Dependencies
- **Visual Studio 2019/2022** (Windows) or **Build Essential** (Linux)
- **Git** for version control and updates

## Installation & Setup

### Prerequisites
1. Install OLLAMA from https://ollama.ai/
2. Pull a model: `ollama pull llama3`
3. Start OLLAMA service: `ollama serve`

### Building the Project
```bash
# Windows - Quick build using batch script
build.bat

# Linux/macOS - Quick build using shell script  
./build.sh

# Manual CMake build (all platforms)
mkdir build
cd build
cmake ..
cmake --build . --config Release

# Windows - Using Visual Studio directly
mkdir build
cd build
cmake .. -G "Visual Studio 16 2019"
cmake --build . --config Release

# Alternative: Direct compilation (if dependencies are installed)
g++ -std=c++17 -Iinclude -O2 src/*.cpp src/core/*.cpp src/utils/*.cpp -lcurl -o cybersec_tool.exe
```

### Quick Start Validation
```powershell
# Windows PowerShell - Validate project setup
.\test_runner.bat

# Run demonstration  
.\demo.bat

# Check build output
Get-ChildItem .\build\bin\Release\
```

## Usage
```bash
# Windows PowerShell - Basic log analysis
.\build\bin\Release\CybersecurityTool.exe --input samples\sample_syslog.log --format syslog --output report.txt

# Windows PowerShell - Windows Event log analysis
.\build\bin\Release\CybersecurityTool.exe --input samples\sample_windows.json --format windows --output windows_report.txt

# Windows PowerShell - CSV alert analysis
.\build\bin\Release\CybersecurityTool.exe --input samples\sample_alerts.csv --format csv --output alerts_summary.txt

# Windows PowerShell - Custom OLLAMA model
.\build\bin\Release\CybersecurityTool.exe --input logs.log --model mistral --prompt "Analyze for APT indicators"

# Windows CMD - Basic log analysis (alternative)
build\bin\Release\CybersecurityTool.exe --input samples\sample_syslog.log --format syslog --output report.txt

# Linux/macOS - Basic log analysis
./build/bin/CybersecurityTool --input samples/sample_syslog.log --format syslog --output report.txt

# Test mode (no external dependencies required)
.\build\bin\Release\CybersecurityTool.exe --test-mode --verbose
```

## Sample Input/Output

### Input (sample_syslog.log)
```
Jan 15 10:23:45 server1 sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:46 server1 sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 10:25:12 server1 kernel: iptables: DROP IN=eth0 OUT= SRC=10.0.0.5 DST=192.168.1.1
```

### Output (Generated Summary)
```
=== CYBERSECURITY LOG ANALYSIS REPORT ===
Generated: 2025-01-15 14:30:21
Model: llama3

THREAT SUMMARY:
- HIGH PRIORITY: Brute force SSH attack detected from 192.168.1.100
- MEDIUM PRIORITY: Suspicious network traffic blocked by firewall

DETAILED ANALYSIS:
1. SSH Brute Force Attack (Priority: HIGH)
   - Source IP: 192.168.1.100
   - Target accounts: root, admin
   - Recommendation: Block source IP, enable fail2ban

2. Firewall Drops (Priority: MEDIUM)
   - Internal source attempting external access
   - May indicate lateral movement or data exfiltration

RECOMMENDED ACTIONS:
- Immediate IP blocking for 192.168.1.100
- Review user account security policies
- Investigate internal host 10.0.0.5 activity
```

## Security Considerations
- **Input Sanitization**: All log entries validated against XSS, SQL injection, and command injection
- **Memory Safety**: RAII patterns, smart pointers, and bounds checking throughout
- **Secure Communication**: TLS/SSL support for OLLAMA API with certificate validation  
- **Path Traversal Protection**: File path validation and sandboxing for log file access
- **Error Handling**: Comprehensive exception handling with secure error messages
- **Resource Management**: Automatic cleanup and leak prevention
- **Logging Security**: Sensitive data sanitization in audit logs
- **API Security**: Rate limiting and timeout protection for external service calls

## Testing

### ⚠️ Important: Build First
Before running any tests, you must build the project first:
```powershell
# Option 1: Use the build script
.\build.bat

# Option 2: Manual CMake build
mkdir build
cd build
cmake ..
cmake --build . --config Release
cd ..
```

### Running Tests
```powershell
# Windows PowerShell - Run unit tests (after building)
.\build\bin\Release\unit_tests.exe

# Windows CMD - Run unit tests (alternative)
build\bin\Release\unit_tests.exe

# Linux/macOS - Run unit tests (after building)
./build/bin/unit_tests

# Test with sample data (Windows PowerShell)
.\build\bin\Release\CybersecurityTool.exe --test-mode --verbose

# Test with sample data (Windows CMD)
build\bin\Release\CybersecurityTool.exe --test-mode --verbose

# Test with sample data (Linux/macOS)
./build/bin/CybersecurityTool --test-mode --verbose

# Test with actual log files (Windows PowerShell)
.\build\bin\Release\CybersecurityTool.exe --input samples\sample_syslog.log --format syslog --output test_report.txt
```

## Troubleshooting & FAQ

### Common Issues
1. **OLLAMA Connection Failed**
   - Ensure OLLAMA is running: `ollama serve`
   - Check if model is pulled: `ollama list`
   - Verify port 11434 is accessible
   - Use `--test-mode` flag to test without OLLAMA

2. **Build Errors**
   - Install Visual Studio Build Tools or full VS 2019/2022
   - Ensure CMake 3.15+ is installed and in PATH
   - Check C++17 compiler support
   - Run `.\test_runner.bat` to validate setup

3. **Sample File Errors**
   - Verify sample files exist in `samples/` directory
   - Check file permissions and encoding (UTF-8)
   - Use absolute paths if relative paths fail

4. **PowerShell Path Issues**
   - Use `.\build\bin\Release\CybersecurityTool.exe` (with dot-slash prefix) in PowerShell
   - Or use `build\bin\Release\CybersecurityTool.exe` in Command Prompt (CMD)
   - Build the project first before attempting to run executables

5. **Executable Not Found**
   - Ensure project is built: run `.\build.bat` or manual CMake build
   - Check that build completed successfully without errors
   - Verify executables exist in `.\build\bin\Release\` directory

### Performance Tips
- Use `--verbose` flag for detailed execution information
- Large log files (>100MB) will be processed in chunks
- Consider using `--model mistral` for faster analysis on smaller datasets
- Enable test mode (`--test-mode`) for development and debugging

### Command Line Options
```powershell
# Windows PowerShell syntax
.\build\bin\Release\CybersecurityTool.exe [OPTIONS]

# Options:
--input <file>        # Input log file path
--format <type>       # Log format: syslog, windows, csv, auto
--output <file>       # Output report file path  
--model <name>        # OLLAMA model: llama3, mistral, codellama
--prompt <text>       # Custom analysis prompt
--test-mode          # Run without external dependencies
--verbose            # Enable detailed logging
--help               # Show usage information

# Examples:
.\build\bin\Release\CybersecurityTool.exe --help
.\build\bin\Release\CybersecurityTool.exe --test-mode --verbose
.\build\bin\Release\CybersecurityTool.exe --input "C:\logs\security.log" --format auto --output report.txt
```

## Team Contributions
See [TEAM_ROLES.md](docs/TEAM_ROLES.md) for detailed breakdown of individual contributions and [FINAL_REPORT.md](docs/FINAL_REPORT.md) for project completion summary.

## Additional Resources
- **Installation Guide**: See [INSTALL.md](INSTALL.md) for detailed setup instructions
- **Project Demo**: Run `demo.bat` (Windows) for a complete demonstration  
- **Sample Output**: View [PROJECT_DEMO.txt](PROJECT_DEMO.txt) for expected analysis results
- **Configuration**: Check `.vscode/` folder for VS Code workspace settings

## License
This project is developed for educational purposes as part of CISA cybersecurity training and demonstration of secure coding practices in C++17.
