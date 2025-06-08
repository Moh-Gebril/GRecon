# GRecon

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.6+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-GPL%20v3-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/Version-1.0.0-green.svg" alt="Version">
</div>

<p align="center">
  <b>Advanced Network Reconnaissance & Vulnerability Assessment Tool</b><br>
  <i>Efficient Port Discovery • Intelligent Nmap Integration • Automated NSE Script Selection</i>
</p>

## Overview

GRecon is a professional network reconnaissance and vulnerability assessment tool designed for penetration testers and security professionals. Created by Mohamed Gebril, it provides a comprehensive framework for efficient port scanning, service detection, and vulnerability assessment in a single, modular package.

The tool builds on the legacy of Threader3000 but has been completely redesigned with a focus on professional code structure, enhanced features, and better usability.

### Key Features

- **Multi-threaded Port Scanner**: Rapidly identifies open ports using efficient threading techniques
- **Intelligent Nmap Integration**: Generates and executes optimized Nmap scans based on discovered ports
- **NSE Script Automation**: Automatically selects and runs appropriate NSE scripts based on detected services
- **Per-Service Analysis**: Performs service-specific security checks with customized NSE scripts
- **Professional Reporting**: Exports results in multiple formats (JSON, XML, HTML)
- **Flexible CLI Interface**: Comprehensive command-line options for various scanning scenarios
- **Color-Coded Output**: Easily identify important findings with intuitive color formatting
- **Modular Design**: Well-structured codebase following Python best practices

## Installation

### Prerequisites

- Python 3.6 or higher
- Nmap (required for advanced scanning features)

### Installation Method

```bash
# Clone the repository
git clone https://github.com/Moh-Gebril/grecon.git

# Navigate to the directory
cd GRecon

# Install using Make
make install
```

## Usage

GRecon can be used in various ways, from simple port scanning to comprehensive vulnerability assessment.

### Basic Usage

```bash
# Basic port scan
grecon -t example.com

# Specify port range and timeout
grecon -t 192.168.1.1 -p 1-1000 --timeout 0.5 --threads 300

# Full scan with Nmap and NSE integration
grecon -t 10.0.0.1 --nmap --nse
```

### Advanced Options

```bash
# Export results in all formats
grecon -t example.com --export-all --output-dir ~/scans

# Use specific Nmap scan type with NSE scripts
grecon -t 192.168.1.100 --nmap --nmap-scan-type comprehensive --nse --nse-category vuln

# Specify NSE script safety level
grecon -t 10.0.0.1 --nmap --nse --nse-safety default
```

### Command Line Options

For a full list of command line options:

```bash
grecon --help
```

## Features in Detail

### Port Scanning

- Multi-threaded scanning for maximum efficiency
- Configurable timeouts and thread counts
- Detailed output showing open ports and services

### Nmap Integration

- Intelligent Nmap command generation based on discovered ports
- Multiple predefined scan profiles:
  - **default**: Balanced scan with service detection and default scripts
  - **quick**: Fast scan with minimal resource usage
  - **comprehensive**: Thorough scan with advanced options
  - **stealth**: Reduced footprint scan for sensitive environments
  - **udp**: UDP port scanning
  - **all**: Complete scan of all ports and services

### NSE Script Automation

- Automatic service detection and appropriate script selection
- Per-service NSE script execution with unique output files
- Safety controls to prevent accidental DoS or intrusive scanning
- Custom script categories and selection options

### Professional Output

- Terminal output with color-coded information:
  - Open ports highlighted in green
  - Script outputs in magenta
  - Vulnerabilities in red
  - Headers and important information in cyan
- Results saved to organized output files:
  - JSON export for machine parsing
  - XML format for compatibility with other tools
  - Professional HTML reports for client presentations

## Output Files

GRecon creates several output files in the results directory:

- **nmap_[scan_type].nmap**: Standard Nmap output format
- **nmap_[scan_type].gnmap**: Grepable Nmap format
- **nmap_[scan_type].xml**: XML format for integration with other tools
- **nse_[service]_[port].nmap**: Service-specific NSE script results
- **[target]_[timestamp].json/.xml/.html**: Comprehensive scan results in various formats

## Project Structure

The project follows a professional, modular design:

```
GRecon/
├── grecon/
│   ├── core/
│   │   ├── scanner.py       # Core scanning functionality
│   │   ├── nmap_engine.py   # Nmap integration
│   │   └── nse_handler.py   # NSE scripts handler
│   ├── utils/
│   │   ├── banner.py        # Professional banner display
│   │   ├── output.py        # Output formatting functions
│   │   └── validator.py     # Input validation
│   └── cli.py               # Command-line interface
├── tests/                   # Unit tests
├── requirements.txt         # Dependencies
├── setup.py                 # Package setup
├── Makefile                 # Build automation
└── README.md                # Documentation
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Distributed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for more information.

## Acknowledgements

- This tool is a complete rewrite and enhancement of the original Threader3000 by The Mayor
- Special thanks to the Nmap project for their incredible scanning engine

## Author

**Mohamed Gebril**

- GitHub: [https://github.com/Moh-Gebril](https://github.com/Moh-Gebril)

---

<div align="center">
  <p>⚠️ <b>For ethical penetration testing and security assessment purposes only</b> ⚠️</p>
  <p>Use only on systems you own or have explicit permission to scan.</p>
</div>
