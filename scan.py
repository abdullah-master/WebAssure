import os
import subprocess
import json
from email_script import send_email 
from zapv2 import ZAPv2
import time
import datetime

ZAP_API_KEY = 'qv8j35dm4mu521ihth60imjbu3'  # Updated API key
ZAP_ADDRESS = '127.0.0.1'
ZAP_PORT = '8080'

def load_email_config():
    try:
        # Load email configuration from the JSON file
        with open("email_config.json", "r") as config_file:
            email_config = json.load(config_file)
        return email_config
    except Exception as e:
        print(f"Error loading email configuration: {e}")
        return None


def run_nikto(target_url, output_file, tuning_options=""):
    try:
        print("[*] Running Nikto Scan...")
        
        nikto_path = "C:\\Program Files\\nikto\\program\\nikto.pl"
        perl_path = "C:\\Strawberry\\perl\\bin\\perl.exe"
        
        # Updated command with SSL support and JSON output
        nikto_command = [
            perl_path,
            nikto_path,
            "-h", target_url,
            "-ssl",  # Add SSL support
            "-Format", "json",  # Use JSON format
            "-o", os.path.abspath(output_file),
            "-Plugins", "@@DEFAULT;tests(,all)",  # Updated from -mutate
            "-Tuning", tuning_options if tuning_options else "123"
        ]

        print(f"[*] Executing command: {' '.join(nikto_command)}")
        
        # Run process with real-time output
        process = subprocess.Popen(
            nikto_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Print output in real-time
        output_text = []
        while True:
            output = process.stdout.readline()
            if output:
                print(output.strip())
                output_text.append(output)
            if process.poll() is not None:
                break
        
        # Get remaining output and errors
        stdout, stderr = process.communicate()
        if stdout:
            print(stdout)
            output_text.append(stdout)
        if stderr:
            print("[-] Errors:", stderr)

        if process.returncode != 0:
            raise Exception(f"Nikto failed with return code {process.returncode}")

        # Join all output
        complete_output = ''.join(output_text)

        # Parse output directly from command output
        nikto_results = parse_nikto_output(complete_output)

        # Add scan metadata
        return {
            "scan_status": "completed",
            "host": target_url,
            "ip": nikto_results.get("ip", "N/A"),
            "port": nikto_results.get("port", "N/A"),
            "hostname": nikto_results.get("hostname", "N/A"),
            "banner": nikto_results.get("banner", "No banner retrieved"),
            "ssl_info": nikto_results.get("ssl_info", {}),
            "vulnerabilities": nikto_results.get("vulnerabilities", [])
        }
            
    except Exception as e:
        print(f"[-] Error during Nikto scan: {e}")
        if hasattr(e, 'stderr'):
            print(f"[-] Error details: {e.stderr}")
        return {
            "scan_status": "error",
            "host": target_url,
            "error": str(e)
        }

def extract_value(text, prefix, default="N/A"):
    """Extract value from Nikto output text."""
    try:
        start = text.index(prefix) + len(prefix)
        end = text.index("\n", start)
        return text[start:end].strip()
    except:
        return default

def parse_vulnerabilities(text):
    """Parse vulnerabilities from Nikto output text."""
    vulns = []
    for line in text.split('\n'):
        if line.startswith('+'):
            vulns.append({
                "id": "N/A",
                "method": "GET",
                "msg": line.strip('+ '),
                "references": ""
            })
    return vulns

def categorize_vulnerability(msg):
    """Categorize vulnerability and return appropriate ID prefix."""
    categories = {
        'SQL': ['sql', 'database', 'injection', 'mysql', 'postgresql', 'oracle'],
        'XSS': ['xss', 'cross-site scripting', 'script injection'],
        'CSRF': ['csrf', 'cross-site request forgery'],
        'AUTH': ['authentication', 'login', 'password', 'credential'],
        'INFO': ['information disclosure', 'info leak', 'server info'],
        'CONFIG': ['configuration', 'setup', 'default installation'],
        'FILE': ['file upload', 'directory', 'file inclusion'],
        'SSL': ['ssl', 'tls', 'certificate', 'cipher'],
        'HEADER': ['header', 'http headers', 'security headers'],
        'INJECT': ['injection', 'command', 'code execution'],
        'DOS': ['denial of service', 'dos', 'buffer overflow']
    }
    
    msg_lower = msg.lower()
    for cat, keywords in categories.items():
        if any(keyword in msg_lower for keyword in keywords):
            return cat
    
    return 'MISC'  # Default category for unclassified vulnerabilities

def parse_nikto_output(output_text):
    """Parse Nikto console output when JSON isn't available."""
    results = {
        "ip": "",
        "hostname": "",
        "port": "",
        "vulnerabilities": [],
        "banner": "",
        "ssl_info": {}
    }
    
    current_section = None
    ssl_info = {}
    
    lines = output_text.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
            
        # Extract basic information
        if line.startswith('+ Target IP:'):
            # Handle multiple IPs
            ips = line.split(':', 1)[1].strip()
            results['ip'] = ips.split(',')[0].strip()  # Use first IP
        elif line.startswith('+ Target Hostname:'):
            results['hostname'] = line.split(':', 1)[1].strip()
        elif line.startswith('+ Target Port:'):
            results['port'] = line.split(':', 1)[1].strip()
        elif line.startswith('+ Server:'):
            results['banner'] = line.split(':', 1)[1].strip()
        # SSL Information
        elif line.startswith('+ SSL Info:'):
            current_section = 'ssl'
            # Look ahead for SSL details
            for ssl_line in lines[i+1:i+4]:
                ssl_line = ssl_line.strip()
                if ssl_line.startswith(('Subject:', 'Ciphers:', 'Issuer:')):
                    key, value = ssl_line.split(':', 1)
                    ssl_info[key.strip()] = value.strip()
            results['ssl_info'] = ssl_info
            current_section = None
        # Vulnerabilities
        elif line.startswith('+') and not any(x in line for x in [
            'Start Time:', 'End Time:', 'SSL Info:', '0 error(s)', 'host(s) tested',
            'Getting links', 'Scan completed', 'Target IP:', 'Target Hostname:',
            'Target Port:', 'Server:'
        ]):
            msg = line.strip('+ ')
            
            # Skip summary lines
            if any(x in msg for x in ['Scan terminated:', 'requests made in']):
                continue
            
            # Determine vulnerability category
            category = categorize_vulnerability(msg)
            
            # Extract references
            references = []
            if 'See:' in msg:
                parts = msg.split('See:')
                msg = parts[0].strip()
                references.append(parts[1].strip())
            
            results['vulnerabilities'].append({
                'id': category,  # Use category directly as ID
                'method': 'GET',
                'msg': msg,
                'references': references[0] if references else ""
            })

    return results

def extract_references(msg):
    """Extract references from vulnerability message."""
    references = []
    
    # Look for references after "See:" or similar indicators
    if 'See:' in msg:
        ref_part = msg.split('See:')[1].strip()
        references.append(ref_part)
    elif 'Reference:' in msg:
        ref_part = msg.split('Reference:')[1].strip()
        references.append(ref_part)
    
    # Extract URLs
    urls = []
    words = msg.split()
    for word in words:
        if word.startswith(('http://', 'https://')):
            urls.append(word)
    
    references.extend(urls)
    return ', '.join(list(dict.fromkeys(references)))  # Remove duplicates

def run_owasp_zap(target_url, output_file, zap_config=None):
    try:
        print("[*] Connecting to OWASP ZAP...")
        
        # Initialize ZAP client with the new API key
        zap = ZAPv2(apikey=ZAP_API_KEY, 
                   proxies={'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}', 
                           'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'})
        
        try:
            version = zap.core.version
            print(f"[+] Connected to ZAP {version}")
        except Exception as e:
            print(f"[-] Failed to connect to ZAP: {e}")
            print("[-] Please ensure ZAP is running on {ZAP_ADDRESS}:{ZAP_PORT}")
            return {"error": "ZAP connection failed"}

        # Access target
        print(f'[*] Accessing target {target_url}')
        try:
            zap.urlopen(target_url)
            time.sleep(2)
        except Exception as e:
            print(f"[-] Failed to access target: {e}")
            return {"error": f"Could not access {target_url}"}

        # Spider scan
        print('[*] Starting spider scan...')
        scan_id = zap.spider.scan(target_url)
        
        while int(zap.spider.status(scan_id)) < 100:
            print(f'Spider progress: {zap.spider.status(scan_id)}%')
            time.sleep(2)
        
        print('[+] Spider scan completed')
        
        # Active scan
        print('[*] Starting active scan...')
        scan_id = zap.ascan.scan(target_url)
        
        while int(zap.ascan.status(scan_id)) < 100:
            print(f'Scan progress: {zap.ascan.status(scan_id)}%')
            time.sleep(5)
        
        print('[+] Active scan completed')

        # Get and format results with metadata
        alerts = zap.core.alerts()
        formatted_alerts = []
        
        for alert in alerts:
            formatted_alert = {
                'name': alert.get('name', ''),
                'risk': alert.get('risk', ''),
                'confidence': alert.get('confidence', ''),
                'description': alert.get('description', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'url': alert.get('url', ''),
                'param': alert.get('param', ''),
                'evidence': alert.get('evidence', ''),
                'cweid': alert.get('cweid', ''),
                'wascid': alert.get('wascid', '')
            }
            formatted_alerts.append(formatted_alert)

        # Add metadata and site information
        results = {
            'scan_status': 'completed',
            'metadata': {
                'programName': 'OWASP ZAP',
                'version': zap.core.version,
                'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
                'site': {
                    'name': target_url,
                    'host': target_url.split('://')[1].split('/')[0],
                    'port': '443' if target_url.startswith('https') else '80',
                    'ssl': 'true' if target_url.startswith('https') else 'false'
                }
            },
            'alerts': formatted_alerts,
            'summary': {
                'total_alerts': len(formatted_alerts),
                'high_risks': len([a for a in formatted_alerts if a['risk'] == 'High']),
                'medium_risks': len([a for a in formatted_alerts if a['risk'] == 'Medium']),
                'low_risks': len([a for a in formatted_alerts if a['risk'] == 'Low'])
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        # Return results in a properly structured format
        return {
            "metadata": {
                "programName": "OWASP ZAP",
                "version": zap.core.version,
                "generated": time.strftime('%Y-%m-%d %H:%M:%S'),
                "site": {
                    "name": target_url,
                    "host": target_url.split('://')[1].split('/')[0],
                    "port": '443' if target_url.startswith('https') else '80',
                    "ssl": 'true' if target_url.startswith('https') else 'false'
                }
            },
            "alerts": alerts,
            "summary": {
                "total_alerts": 0,
                "high_risks": len([a for a in alerts if a['risk'] == 'High']),
                "medium_risks": len([a for a in alerts if a['risk'] == 'Medium']),
                "low_risks": len([a for a in alerts if a['risk'] == 'Low'])
            }
        }

    except Exception as e:
        error_msg = f"Error during OWASP ZAP scan: {str(e)}"
        print(f"[-] {error_msg}")
        return {
            "metadata": {
                "programName": "OWASP ZAP",
                "version": "Error",
                "generated": time.strftime('%Y-%m-%d %H:%M:%S'),
                "site": {
                    "name": target_url,
                    "host": "Error",
                    "port": "Error",
                    "ssl": "Error"
                }
            },
            "alerts": [],
            "summary": {
                "total_alerts": 0,
                "high_risks": 0,
                "medium_risks": 0,
                "low_risks": 0
            },
            "error": error_msg
        }

from db_operations import DatabaseHandler

def save_results(target_url, nikto_results, zap_results, file_paths):
    """Save scan results to JSON files and MongoDB"""
    try:
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(file_paths['combined_output'])
        os.makedirs(output_dir, exist_ok=True)

        # Save individual results first
        results_saved = []
        for result_type, result_data in [('nikto', nikto_results), ('zap', zap_results)]:
            try:
                with open(file_paths[f'{result_type}_output'], 'w') as f:
                    json.dump(result_data, f, indent=4)
                results_saved.append(True)
            except Exception as e:
                print(f"[-] Error saving {result_type} results: {e}")
                results_saved.append(False)

        if not any(results_saved):
            raise Exception("Failed to save any scan results")

        # Prepare and save combined results
        combined_results = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target_url': target_url,
            'scan_metrics': {
                'zap': {
                    'high_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'High']),
                    'medium_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'Medium']),
                    'low_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'Low']),
                    'info_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'Informational'])
                },
                'nikto': {
                    'total_vulnerabilities': len(nikto_results.get('vulnerabilities', [])),
                    'high_risks': len([v for v in nikto_results.get('vulnerabilities', []) 
                                     if v['id'].startswith(('INJECT', 'SQL', 'XSS'))]),
                    'medium_risks': len([v for v in nikto_results.get('vulnerabilities', []) 
                                       if v['id'].startswith(('CONFIG', 'SSL', 'AUTH'))]),
                    'low_risks': len([v for v in nikto_results.get('vulnerabilities', []) 
                                    if v['id'].startswith(('INFO', 'HEADER'))])
                }
            },
            'file_locations': {path_type: os.path.abspath(path) for path_type, path in file_paths.items()},
            'nikto_results': nikto_results,
            'zap_results': zap_results
        }

        # Save to MongoDB
        try:
            db_handler = DatabaseHandler()
            doc_id = db_handler.save_scan_results(
                target_url=target_url,
                output_dir=output_dir,
                nikto_results=nikto_results,
                zap_results=zap_results
            )
            if not doc_id:
                raise Exception("Failed to get document ID from MongoDB")
                
            # Ensure scan_id is included in the return value
            combined_results['scan_id'] = str(doc_id)
            
        except Exception as e:
            print(f"[-] MongoDB save error: {e}")
            return None

        # Save combined results to file
        with open(file_paths['combined_output'], 'w') as f:
            json.dump(combined_results, f, indent=4)

        return combined_results

    except Exception as e:
        print(f"[-] Critical error saving results: {e}")
        return None

def main():
    target_url = input("Enter the target URL: ").strip()
    
    # Create output directory structure with timestamp
    output_base = os.path.join(os.getcwd(), "output")
    scan_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(output_base, scan_time)
    
    try:
        os.makedirs(scan_dir, exist_ok=True)
        print(f"[+] Created scan directory: {scan_dir}")
    except Exception as e:
        print(f"[-] Error creating output directory: {e}")
        return None

    file_paths = {
        'nikto_output': os.path.join(scan_dir, f"nikto_{scan_time}.json"),
        'zap_output': os.path.join(scan_dir, f"zap_{scan_time}.json"),
        'combined_output': os.path.join(scan_dir, f"combined_{scan_time}.json")
    }

    # Use the ThreadedScanner from the new module
    from threaded_scanner import ThreadedScanner
    scanner = ThreadedScanner()
    results = scanner.run_concurrent_scan(target_url, file_paths)

    # Save results
    save_results(target_url, results.get('nikto', {}), results.get('zap', {}), file_paths)

    print(f"[+] All scan results saved in: {scan_dir}")
    return results

if __name__ == "__main__":
    main()
