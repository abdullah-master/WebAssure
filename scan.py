import os
import subprocess
import json
from email_script import send_email 
from zapv2 import ZAPv2
import time
import datetime

# ZAP configuration for connecting to running GUI instance
ZAP_API_KEY = 'qv8j35dm4mu521ihth60imjbu3'  # Your API key from ZAP GUI
ZAP_ADDRESS = 'localhost'  # Default ZAP GUI address
ZAP_PORT = '8080'  # Default ZAP GUI port

def load_email_config():
    try:
        # Load email configuration from the JSON file
        with open("email_config.json", "r") as config_file:
            email_config = json.load(config_file)
        return email_config
    except Exception as e:
        print(f"Error loading email configuration: {e}")
        return None


def run_nikto(target_url, output_file, config=None):
    try:
        print("[*] Running Nikto Scan...")
        
        nikto_path = "C:\\Program Files\\nikto\\program\\nikto.pl"
        perl_path = "C:\\Strawberry\\perl\\bin\\perl.exe"
        
        # Build scan options based on config
        scan_options = []
        if config and isinstance(config, dict):
            if config.get('tests', {}).get('sqli'):
                scan_options.extend(['-Tuning', '9'])
            if config.get('tests', {}).get('headers'):
                scan_options.extend(['-Tuning', '4'])
            if config.get('tests', {}).get('ssl'):
                scan_options.extend(['-Tuning', '2'])
            if config.get('tests', {}).get('auth'):
                scan_options.extend(['-Tuning', '7'])
        
        # Updated command with options
        nikto_command = [
            perl_path,
            nikto_path,
            "-h", target_url,
            "-ssl",
            "-Format", "json",
            "-o", os.path.abspath(output_file)
        ] + scan_options
        
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

        # Check if JSON output file exists and is valid
        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results = json.load(f)
                    if isinstance(results, dict):
                        results['scan_status'] = 'completed'
                        return results
        except Exception as e:
            print(f"[-] Error reading JSON output: {e}")

        # Fallback to parsing command output if JSON fails
        nikto_results = parse_nikto_output(''.join(output_text))
        
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
    
    if not output_text:
        return results
        
    current_section = None
    ssl_info = {}
    
    try:
        # First try to parse as JSON
        try:
            json_data = json.loads(output_text)
            if isinstance(json_data, dict):
                return json_data
        except json.JSONDecodeError:
            pass  # Not JSON, continue with text parsing
        
        lines = output_text.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
                
            # Extract basic information
            if '+ Target IP:' in line:
                results['ip'] = line.split(':', 1)[1].strip().split(',')[0].strip()
            elif '+ Target Hostname:' in line:
                results['hostname'] = line.split(':', 1)[1].strip()
            elif '+ Target Port:' in line:
                results['port'] = line.split(':', 1)[1].strip()
            elif '+ Server Banner:' in line or '+ Server:' in line:
                results['banner'] = line.split(':', 1)[1].strip()
            # SSL Information
            elif '+ SSL Info:' in line or 'SSL Certificate:' in line:
                current_section = 'ssl'
                continue
                
            if current_section == 'ssl':
                if line.startswith(('Subject:', 'Ciphers:', 'Issuer:')):
                    key, value = line.split(':', 1)
                    ssl_info[key.strip()] = value.strip()
                else:
                    current_section = None
                    
            # Vulnerabilities - look for lines starting with + that aren't headers
            elif line.startswith('+') and not any(x in line for x in [
                'Start Time:', 'End Time:', 'SSL Info:', '0 error(s)', 'host(s) tested',
                'Getting links', 'Scan completed', 'Target IP:', 'Target Hostname:',
                'Target Port:', 'Server:', 'Scan Settings:'
            ]):
                msg = line.strip('+ ')
                
                # Skip summary lines
                if any(x in msg.lower() for x in [
                    'scan terminated:', 'requests made in', 'items checked:',
                    'host summary'
                ]):
                    continue
                
                # Extract references
                references = ""
                if 'See:' in msg:
                    msg_parts = msg.split('See:')
                    msg = msg_parts[0].strip()
                    references = msg_parts[1].strip()
                
                # Determine vulnerability category
                category = categorize_vulnerability(msg)
                
                vuln = {
                    'id': category,
                    'method': 'GET',
                    'msg': msg,
                    'references': references
                }
                
                results['vulnerabilities'].append(vuln)
        
        results['ssl_info'] = ssl_info
        return results
        
    except Exception as e:
        print(f"[-] Error parsing Nikto output: {e}")
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

def run_owasp_zap(target_url, output_file, config=None):
    try:
        print("[*] Connecting to ZAP GUI...")
        
        # Initialize ZAP connection with retries
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                zap = ZAPv2(apikey=ZAP_API_KEY, 
                          proxies={'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}', 
                                  'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'})
                # Test connection
                version = zap.core.version
                print(f"[+] Connected to ZAP GUI (version {version})")
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    raise Exception(f"Failed to connect to ZAP GUI after {max_retries} attempts: {e}")
                print(f"[-] Connection attempt {attempt + 1} failed, retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)

        # Configure scan based on duration
        if config and 'duration' in config:
            scan_time = {
                'quick': 1,
                'standard': 5,
                'deep': 10
            }.get(config['duration'], 5)  # Default to standard
        else:
            scan_time = 5  # Default scan time in minutes

        # Configure scan policies based on selected tests
        policy_name = None
        if config and 'tests' in config:
            try:
                # Generate a unique policy name using timestamp
                timestamp = int(time.time())
                policy_name = f'policy_{timestamp}'
                
                # First try to remove any existing policy with the same name
                try:
                    zap.ascan.remove_scan_policy(policy_name)
                except Exception:
                    pass  # Policy doesn't exist, which is fine

                # Create a new policy
                print(f"[*] Creating scan policy: {policy_name}")
                zap.ascan.add_scan_policy(policy_name)

                # Get all scan IDs first
                all_scanners = zap.ascan.scanners()
                scanner_ids = {
                    'xss': [],
                    'sqli': [],
                    'auth_issues': [],
                    'headers': []
                }

                # Categorize scanners
                for scanner in all_scanners:
                    scanner_id = scanner['id']
                    name = scanner['name'].lower()
                    if 'xss' in name or 'cross' in name:
                        scanner_ids['xss'].append(scanner_id)
                    elif 'sql' in name or 'injection' in name:
                        scanner_ids['sqli'].append(scanner_id)
                    elif 'auth' in name or 'login' in name:
                        scanner_ids['auth_issues'].append(scanner_id)
                    elif 'header' in name:
                        scanner_ids['headers'].append(scanner_id)

                # Disable all scanners first
                for scanner in all_scanners:
                    zap.ascan.disable_scanners(scanner['id'], policy_name)

                # Enable selected scanners
                for test_type, enabled in config['tests'].items():
                    if enabled and test_type in scanner_ids:
                        for scanner_id in scanner_ids[test_type]:
                            try:
                                print(f"[*] Enabling scanner {scanner_id} for {test_type}")
                                zap.ascan.enable_scanners(scanner_id, policy_name)
                            except Exception as e:
                                print(f"[-] Error enabling scanner {scanner_id}: {e}")

            except Exception as e:
                print(f"[-] Error configuring scan policy: {e}")
                policy_name = None

        # Access the target through ZAP proxy
        print(f"[*] Accessing target through ZAP: {target_url}")
        zap.urlopen(target_url)
        time.sleep(2)  # Wait for the request to complete

        # Spider the target
        print("[*] Starting spider...")
        scan_id = zap.spider.scan(target_url)
        time.sleep(2)

        # Wait for spider to complete
        while int(zap.spider.status(scan_id)) < 100:
            print(f"[*] Spider progress: {zap.spider.status(scan_id)}%")
            time.sleep(2)

        print("[*] Spider completed")

        # Start the active scan
        print("[*] Starting active scan...")
        if policy_name:
            print(f"[*] Using custom policy: {policy_name}")
            scan_id = zap.ascan.scan(target_url, scanpolicyname=policy_name)
        else:
            print("[*] Using default policy")
            scan_id = zap.ascan.scan(target_url)

        # Wait for the scan to complete
        start_time = time.time()
        timeout = scan_time * 60  # Convert minutes to seconds
        
        while int(zap.ascan.status(scan_id)) < 100:
            if time.time() - start_time > timeout:
                print("[-] Scan timeout reached, gathering available results...")
                break
            print(f"[*] Scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(5)

        print("[*] Active scan completed")

        # Clean up the custom policy
        if policy_name:
            try:
                zap.ascan.remove_scan_policy(policy_name)
                print(f"[*] Removed custom policy: {policy_name}")
            except Exception as e:
                print(f"[-] Error removing policy: {e}")

        # Get and format results
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

        # Save results to file
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
                    'ssl': target_url.startswith('https')
                }
            },
            'alerts': formatted_alerts,
            'summary': {
                'total_alerts': len(formatted_alerts),
                'high_risks': len([a for a in formatted_alerts if a['risk'] == 'High']),
                'medium_risks': len([a for a in formatted_alerts if a['risk'] == 'Medium']),
                'low_risks': len([a for a in formatted_alerts if a['risk'] == 'Low']),
                'info_risks': len([a for a in formatted_alerts if a['risk'] == 'Informational'])
            }
        }
        
        # Save to file
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        return results

    except Exception as e:
        error_msg = f"Error during OWASP ZAP scan: {str(e)}"
        print(f"[-] {error_msg}")
        
        # Save error results
        error_results = {
            'scan_status': 'error',
            'metadata': {
                'programName': 'OWASP ZAP',
                'version': 'Error',
                'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
                'site': {
                    'name': target_url,
                    'host': 'Error',
                    'port': 'Error',
                    'ssl': 'Error'
                }
            },
            'alerts': [],
            'summary': {
                'total_alerts': 0,
                'high_risks': 0,
                'medium_risks': 0,
                'low_risks': 0,
                'info_risks': 0
            },
            'error': error_msg
        }
        
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(error_results, f, indent=4)
        except Exception as save_error:
            print(f"[-] Error saving results: {save_error}")
        
        return error_results

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
