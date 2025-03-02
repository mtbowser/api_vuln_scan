# API Security Scanner

A comprehensive tool for security professionals to scan and analyze REST APIs for common security vulnerabilities and misconfigurations.

## Overview

The API Security Scanner is designed to help security teams quickly identify potential security issues in REST APIs before they are deployed to production or as part of regular security audits. This tool performs automated checks for common API security issues including authentication weaknesses, sensitive data exposure, missing rate limiting, verbose error messages, and HTTP method enumeration.

## Features

- **Endpoint Discovery**: Automatically discover API endpoints using a wordlist
- **Authentication Testing**: Detect endpoints missing proper authentication
- **Sensitive Data Detection**: Identify responses containing potentially sensitive information
- **Rate Limiting Analysis**: Check if APIs implement proper rate limiting controls
- **Error Disclosure Testing**: Find endpoints that reveal too much information in error messages
- **HTTP Method Enumeration**: Determine which HTTP methods are supported by each endpoint
- **Multi-threaded Scanning**: Efficiently scan multiple endpoints in parallel
- **Structured Reporting**: Generate clear, readable reports highlighting security issues

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Setup

1. Clone this repository or download the script
2. Install the required dependencies:

```bash
pip install requests rich
```

## Usage

### Basic Usage

To scan an API with a wordlist for endpoint discovery:

```bash
python api_security_scanner.py --url https://api.example.com --wordlist wordlists/api_endpoints.txt
```

### Scan Known Endpoints

To scan specific endpoints without discovery:

```bash
python api_security_scanner.py --url https://api.example.com --endpoints login,users,admin,data
```

### With Authentication

To scan with authorization:

```bash
python api_security_scanner.py --url https://api.example.com --wordlist wordlists/api_endpoints.txt --auth "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Save Results

To save scan results to a JSON file:

```bash
python api_security_scanner.py --url https://api.example.com --wordlist wordlists/api_endpoints.txt --output results.json
```

### Advanced Options

Adjust the number of concurrent threads:

```bash
python api_security_scanner.py --url https://api.example.com --wordlist wordlists/api_endpoints.txt --threads 10
```

## Security Issues Detected

The scanner checks for the following security issues:

1. **Missing Authentication**: Identifies endpoints that don't require authentication but may contain sensitive information.

2. **Sensitive Data Exposure**: Detects responses that may contain sensitive information like passwords, tokens, or private keys.

3. **Missing Rate Limiting**: Checks if the API implements rate limiting to prevent abuse and denial of service attacks.

4. **Error Information Disclosure**: Identifies endpoints that return verbose error messages which could reveal implementation details.

5. **Unnecessary HTTP Methods**: Detects endpoints that support potentially dangerous HTTP methods beyond what's required.

## When To Use This Tool

- **Pre-deployment Testing**: Before releasing a new API to production
- **Regular Security Audits**: As part of scheduled security reviews
- **After Significant Changes**: When an API undergoes major modifications
- **Vendor API Assessment**: When evaluating third-party APIs before integration
- **Security Incident Response**: When investigating potential API security breaches

## How It Works

The scanner operates in several phases:

1. **Discovery Phase**: Makes HTTP requests to potential endpoints based on the wordlist to identify which ones exist
2. **Authentication Testing**: Sends requests without authentication tokens to see if protected resources are accessible
3. **Data Analysis**: Examines responses for patterns indicating sensitive information
4. **Rate Limiting Testing**: Sends multiple rapid requests to check for rate limiting controls
5. **Error Testing**: Sends malformed requests to trigger and analyze error responses
6. **Method Testing**: Tries different HTTP methods to determine which ones the API supports

## Sample Output

```
=== API Security Scanner ===
Discovering API endpoints...
Discovered 5 endpoints
Scanning 5 endpoints for security issues...

Scan Results
┌─────────────────────────────┐
│ Missing Authentication      │
├────────────────────┬────────┤
│ Endpoint           │ Status │
│                    │ Code   │
├────────────────────┼────────┤
│ example.com/public │ 200    │
└────────────────────┴────────┘

┌──────────────────────────────────────────────┐
│ Sensitive Data Exposure                      │
├────────────────────┬─────────────────────────┤
│ Endpoint           │ Sensitive Patterns      │
├────────────────────┼─────────────────────────┤
│ example.com/users  │ password, token, secret │
└────────────────────┴─────────────────────────┘
```

## Security Considerations

This tool is designed for legitimate security testing with proper authorization. Please ensure you have permission to scan the target API before using this tool. Unauthorized scanning may violate terms of service or laws in certain jurisdictions.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to enhance the functionality of this scanner, add new security checks, or improve the reporting.

## License

This project is licensed under the MIT License - see the LICENSE file for details.