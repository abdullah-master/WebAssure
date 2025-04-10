# ZapNik Scanner

## Overview
ZapNik Scanner is a comprehensive web application security assessment tool that combines the power of OWASP ZAP and Nikto scanners. It provides a unified web interface for conducting security scans, managing results, and generating detailed reports.

## Features
- **Integrated Scanning Tools**
  - OWASP ZAP for dynamic application security testing
  - Nikto for web server vulnerability assessment
- **MongoDB Integration** for persistent storage of scan results
- **Email Notifications** for scan completion and reports
- **Web Interface** for easy scan management and result viewing
- **JSON Report Generation** with detailed vulnerability findings

## Prerequisites
- Windows operating system
- Python 3.8 or higher
- MongoDB Community Server
- Perl (for Nikto scanner)
- OWASP ZAP

## Installation

### 1. MongoDB Setup
1. Download MongoDB Community Server from https://www.mongodb.com/try/download/community
2. Run the installer with default settings
3. Start MongoDB service:
```batch
net start MongoDB
```

### 2. Required Software
1. Install Python 3.8+ from https://www.python.org/downloads/
2. Install Perl (Strawberry Perl) from http://strawberryperl.com/
3. Install OWASP ZAP from https://www.zaproxy.org/download/

### 3. Project Setup
1. Clone the repository:
```bash
git clone https://github.com/your-username/ZapNik_Scanner.git
cd ZapNik_Scanner
```

2. Run the setup script:
```bash
setup.bat
```

This script will:
- Check MongoDB installation
- Install required Python packages
- Initialize the database
- Start the application

## Configuration

### MongoDB Configuration
Edit `mongo_config.json`:
```json
{
    "mongo_uri": "mongodb://localhost:27017/",
    "database": "scandb",
    "collection": "scan_reports",
    "nikto": {
        "nikto_path": "C:\\Program Files\\nikto\\program\\nikto.pl",
        "perl_path": "C:\\Strawberry\\perl\\bin\\perl.exe",
        "output_dir": "output"
    }
}
```

### Email Configuration (Optional)
Create `email_config.json`:
```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your-email@gmail.com",
    "app_password": "your-app-password",
    "recipient_email": "recipient@example.com"
}
```

## Usage

### Starting the Application
1. Run `setup.bat`
2. Access the web interface at `http://localhost:3002`

### Performing a Scan
1. Enter the target URL
2. Configure scan options:
   - Nikto tuning options
   - ZAP scanning depth
   - Email notification preferences
3. Start the scan
4. Monitor progress through the web interface

### Viewing Results
- Access scan results through the web interface
- Download JSON reports for detailed analysis
- View historical scans in the MongoDB database

## Project Structure
```
ZapNik_Scanner/
├── app.py              # Main Flask application
├── scan.py            # Scanner implementation
├── init_db.py         # Database initialization
├── setup.bat          # Setup script
├── requirements.txt   # Python dependencies
├── templates/         # HTML templates
├── static/           # Static assets
└── output/           # Scan results
```

## Common Issues and Solutions

### MongoDB Connection Issues
- Ensure MongoDB service is running
- Check MongoDB configuration in `mongo_config.json`
- Verify MongoDB port (27017) is not blocked

### Scanner Issues
- Verify Nikto and Perl paths in configuration
- Check OWASP ZAP is running and accessible
- Ensure proper network connectivity to target

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
This project is licensed under the MIT License.

## Security Notice
Always ensure you have proper authorization before scanning any systems. This tool should only be used for legitimate security testing purposes.