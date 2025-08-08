# Installation and Quick Start Guide

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+), or macOS (10.15+)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 2GB free space for OLLAMA models
- **Network**: Internet connection for initial OLLAMA setup

### Dependencies
- **C++ Compiler**: Visual Studio 2019+ (Windows) or GCC 9+ (Linux/macOS)
- **CMake**: Version 3.16 or later
- **libcurl**: For HTTP requests to OLLAMA
- **OLLAMA**: Local LLM server

## Installation Steps

### 1. Install OLLAMA
```bash
# Visit https://ollama.ai/ and download for your platform
# Or use the following commands:

# Linux/macOS
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# Download and run the installer from https://ollama.ai/
```

### 2. Pull a Language Model
```bash
# Pull the default model (llama3)
ollama pull llama3

# Alternative models (optional)
ollama pull mistral
ollama pull codellama
```

### 3. Start OLLAMA Service
```bash
# Start OLLAMA server
ollama serve

# Verify it's running (should return JSON)
curl http://localhost:11434/api/tags
```

### 4. Build the Cybersecurity Tool

#### Windows (Visual Studio)
```cmd
# Run the build script
build.bat

# Or manually:
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

#### Linux/macOS
```bash
# Install dependencies first
# Ubuntu/Debian:
sudo apt-get install cmake g++ libcurl4-openssl-dev nlohmann-json3-dev

# CentOS/RHEL:
sudo yum install cmake gcc-c++ libcurl-devel json-devel

# macOS (with Homebrew):
brew install cmake curl nlohmann-json

# Build the project
chmod +x build.sh
./build.sh
```

## Quick Start

### 1. Test Mode (Recommended First Run)
```bash
# Windows
cd build
bin\Release\CybersecurityTool.exe --test-mode --verbose

# Linux/macOS
cd build
./bin/CybersecurityTool --test-mode --verbose
```

### 2. Analyze Sample Logs
```bash
# Syslog analysis
CybersecurityTool.exe --input samples/sample_syslog.log --format syslog --output syslog_report.txt

# CSV alerts analysis
CybersecurityTool.exe --input samples/sample_alerts.csv --format csv --output alerts_report.txt

# Windows Event log analysis
CybersecurityTool.exe --input samples/sample_windows.json --format windows --output windows_report.txt
```

### 3. Custom Analysis
```bash
# Analyze your own logs
CybersecurityTool.exe --input /path/to/your/logs.log --format syslog --output custom_report.txt --model llama3

# Use custom prompt
CybersecurityTool.exe --input logs.log --prompt "Focus on APT indicators and lateral movement" --output apt_analysis.txt
```

## Configuration Options

### Command Line Arguments
- `--input FILE`: Input log file to analyze (required)
- `--output FILE`: Output report file (default: cybersec_analysis_report.txt)
- `--format FORMAT`: Log format (syslog, windows, json, csv, auto-detect)
- `--model MODEL`: OLLAMA model to use (default: llama3)
- `--url URL`: OLLAMA server URL (default: http://localhost:11434)
- `--prompt TEXT`: Custom analysis prompt
- `--test-mode`: Run with built-in sample data
- `--verbose`: Enable detailed logging
- `--help`: Show help message

### Example Configurations
```bash
# High-security environment
CybersecurityTool.exe --input security.log --model mistral --prompt "Analyze for advanced persistent threats and zero-day indicators"

# Quick triage
CybersecurityTool.exe --input alerts.csv --prompt "Identify highest priority threats requiring immediate action"

# Network focus
CybersecurityTool.exe --input network.log --prompt "Focus on network intrusions, lateral movement, and data exfiltration"
```

## Troubleshooting

### Common Issues

#### OLLAMA Connection Failed
```
Error: Cannot connect to OLLAMA server at http://localhost:11434
```
**Solution:**
1. Ensure OLLAMA is installed and running: `ollama serve`
2. Check if the service is accessible: `curl http://localhost:11434/api/tags`
3. Verify firewall settings allow connection to port 11434

#### Model Not Found
```
Error: Model 'llama3' not found
```
**Solution:**
1. Pull the model: `ollama pull llama3`
2. List available models: `ollama list`
3. Use an available model with `--model` parameter

#### Build Errors
```
Error: Cannot find libcurl
```
**Solution:**
- **Windows**: Install vcpkg and libcurl: `vcpkg install curl`
- **Linux**: Install dev packages: `sudo apt-get install libcurl4-openssl-dev`
- **macOS**: Install with Homebrew: `brew install curl`

#### Permission Denied
```
Error: Cannot open input file
```
**Solution:**
1. Check file exists and path is correct
2. Ensure read permissions on the log file
3. Use absolute paths if relative paths fail

### Debug Mode
```bash
# Enable verbose logging for troubleshooting
CybersecurityTool.exe --input logs.log --verbose

# Check log file for detailed errors
type cybersec_tool.log    # Windows
cat cybersec_tool.log     # Linux/macOS
```

### Performance Tuning

#### Large Log Files
- Use streaming mode for files > 100MB
- Increase batch size in configuration
- Consider splitting large files into smaller chunks

#### Memory Usage
- Monitor RAM usage during analysis
- Reduce concurrent processing if memory limited
- Use swap space for very large datasets

#### Network Optimization
- Increase OLLAMA timeout for slow responses
- Use local models for better performance
- Consider model quantization for resource-constrained systems

## Security Considerations

### File Permissions
```bash
# Ensure proper file permissions
chmod 600 cybersec_tool.log    # Log file
chmod 644 *.txt                # Report files
chmod 755 CybersecurityTool    # Executable
```

### Network Security
- Run OLLAMA on localhost only (default)
- Use firewall rules to restrict access
- Consider VPN for remote OLLAMA instances

### Data Privacy
- All processing is done locally
- No data sent to external services
- Log files may contain sensitive information - handle appropriately

## Support and Documentation

### Getting Help
- Read the full README.md for detailed information
- Check the docs/ directory for additional documentation
- Review sample files in samples/ directory
- Examine unit tests in tests/ for usage examples

### Reporting Issues
1. Check existing documentation first
2. Enable verbose logging to capture details
3. Include system information and error messages
4. Provide sample input that reproduces the issue

### Contributing
- Follow secure coding practices
- Include unit tests for new features
- Update documentation for changes
- Test on multiple platforms before submitting
