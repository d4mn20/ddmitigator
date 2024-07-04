
# README for DefectDojo OpenAI Integration Script

## Overview
This Python script integrates DefectDojo, an open-source application vulnerability management tool, with OpenAI's language model to provide automated mitigation suggestions for findings (vulnerabilities). The script polls DefectDojo for new findings and uses OpenAI's AI to generate mitigation steps, which are then posted back to the respective findings in DefectDojo.

## Features
- **Automated Polling**: Regularly checks DefectDojo for new findings.
- **AI-Driven Mitigation**: Uses OpenAI's GPT-3.5 Turbo to suggest mitigations.
- **DefectDojo Integration**: Updates findings in DefectDojo with AI-suggested mitigation steps.

## Prerequisites
- Python 3.6 or newer.
- `requests` library for Python.
- Access to a DefectDojo instance with an API token.
- Access to OpenAI API with an API key.

## Installation & Setup
1. **Install Dependencies**:
   ```bash
   pip install requests openai
   ```
2. **Environment Variables**:
   - Set `OPENAI_API_KEY` with your OpenAI API key.
   - Ensure DefectDojo API token and URL are correctly set in the script.

3. **Run the Script**:
   ```bash
   python script_name.py
   ```

## Usage
Once started, the script performs the following actions:
1. Polls the specified DefectDojo instance for new findings.
2. For each new finding, sends the description to OpenAI for mitigation suggestion.
3. Receives the mitigation suggestion and posts it back to the finding in DefectDojo.

## Configuration
- `url`: The URL endpoint of your DefectDojo instance's API.
- `headers`: Set with the appropriate authorization token for DefectDojo.
- `polling_interval`: Time interval (in seconds) between each poll to the DefectDojo API.

## Note
- This script disables SSL verification (`verify=False`) for requests. For production use, ensure SSL certificates are properly set up and verification is enabled.
- Handle your API keys securely and avoid hardcoding them in the script.

## Troubleshooting
- **API Connection Errors**: Check network settings, API keys, and endpoint URLs.
- **SSL Certificate Warnings**: Replace self-signed certificates with CA-issued certificates, or add them to your system's trusted store.

## Disclaimer
This script is intended for educational purposes and should be adapted for production environments according to security best practices.
