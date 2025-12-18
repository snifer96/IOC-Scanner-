# IOC-Scanner-
🎯 Overview  IOC Scanner v2.0 is a comprehensive, web-based threat intelligence platform designed for cybersecurity professionals, incident responders, and threat hunters. This powerful tool integrates with VirusTotal API to provide real-time analysis of Indicators of Compromise (IOCs), enabling rapid threat assessment and security investigations.

IOC Scanner v2.0 - Threat Intelligence Platform

A powerful web-based IOC (Indicators of Compromise) scanner that integrates with VirusTotal API to analyze IP addresses, domains, URLs, and file hashes for potential threats.

Features
Core Scanning Capabilities

    IP Address Analysis: Check reputation, geolocation, and threat scores

    Domain Scanning: Analyze domains for malicious activities

    URL Verification: Scan URLs for phishing, malware, and suspicious content

    File Hash Checking: Validate file hashes against known malware databases

    File Upload & Hash Calculation: Upload files to calculate MD5, SHA-1, SHA-256 hashes

Advanced Features

    Batch Scanning: Process multiple IOCs simultaneously

    Real-time Threat Assessment: Visual threat level indicators (High/Medium/Low)

    Caching System: Reduce API calls and improve performance

    Comprehensive Reporting: Export results in CSV, JSON, HTML formats

    Interactive Charts: Visualize scan statistics with dynamic charts

    Scan History: Maintain and review past scan results

Prerequisites

    Python 3.8 or higher

    VirusTotal API key (free tier available)

    Git (for cloning the repository)

🔧 Installation

1. Clone the Repository
bash

git clone https://github.com/snifer96/IOC-Scanner-.git
cd ioc-scanner-v2

2. Create Virtual Environment
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate

3. Install Dependencies
pip install -r requirements.txt

4. Configure Environment Variables

Create a .env file in the root directory:
env

VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

5. Get Your VirusTotal API Key

    Visit VirusTotal
    Sign up for a free account
    Navigate to your API key
    Copy your API key to the .env file

Usage
Starting the Application

python app.py

The application will start at: http://127.0.0.1:9648

ioc-scanner-v2/
│
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── .env                      # Environment variables (create this)
│
├── templates/
│   └── index.html           # Main web interface
│
├── static/
│   ├── css/
│   │   └── style.css        # Stylesheets
│   └── js/
│       └── script.js        # Frontend JavaScript
│
├── reports/                  # Generated reports (auto-created)
├── uploads/                  # Temporary file uploads (auto-created)
│
└── README.md                 # This file


Configuration Options
Custom Port

Edit the last line in app.py:
python

app.run(host='127.0.0.1', port=5000, debug=True)  # Change port as needed

Cache Duration

Modify in app.py (IOCScanner class):
python

self.cache_duration = timedelta(hours=1)  # Change cache duration

File Size Limit

Adjust in app.py:
python

app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max file size
