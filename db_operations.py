from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import os
import json
from datetime import datetime
import time

class DatabaseHandler:
    def __init__(self, mongo_uri="mongodb://localhost:27017/"):
        try:
            # Add retry logic
            for attempt in range(3):
                try:
                    self.client = MongoClient(mongo_uri, 
                                        serverSelectionTimeoutMS=5000,
                                        connectTimeoutMS=5000,
                                        socketTimeoutMS=5000)
                    # Test connection
                    self.client.server_info()
                    self.db = self.client['scandb']
                    self.collection = self.db['scan_results']
                    
                    # Create indexes
                    self.collection.create_index([("timestamp", ASCENDING)])
                    self.collection.create_index([("target_url", ASCENDING)])
                    
                    print("[+] Connected to MongoDB successfully")
                    break
                except Exception as e:
                    if attempt == 2:  # Last attempt
                        raise
                    print(f"[-] Connection attempt {attempt + 1} failed, retrying...")
                    time.sleep(2)  # Wait before retry
        except Exception as e:
            print(f"[-] MongoDB Connection Error: {e}")
            self.client = None
            raise

    def save_scan_results(self, target_url, output_dir, nikto_results, zap_results):
        try:
            # Calculate metrics
            zap_metrics = {
                'high_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'High']),
                'medium_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'Medium']),
                'low_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'Low']),
                'info_risks': len([a for a in zap_results.get('alerts', []) if a.get('risk') == 'Informational'])
            }

            nikto_metrics = {
                'total_vulnerabilities': len(nikto_results.get('vulnerabilities', [])),
                'high_risks': len([v for v in nikto_results.get('vulnerabilities', []) 
                                 if v['id'].startswith(('INJECT', 'SQL', 'XSS'))]),
                'medium_risks': len([v for v in nikto_results.get('vulnerabilities', []) 
                                   if v['id'].startswith(('CONFIG', 'SSL', 'AUTH'))]),
                'low_risks': len([v for v in nikto_results.get('vulnerabilities', []) 
                                if v['id'].startswith(('INFO', 'HEADER'))])
            }

            # Prepare document with actual scan results
            document = {
                'timestamp': datetime.now(),
                'target_url': target_url,
                'metrics': {
                    'zap': zap_metrics,
                    'nikto': nikto_metrics,
                    'total_risks': sum(zap_metrics.values()) + nikto_metrics['total_vulnerabilities']
                },
                'summary': {
                    'total_high_risks': zap_metrics['high_risks'] + nikto_metrics['high_risks'],
                    'total_medium_risks': zap_metrics['medium_risks'] + nikto_metrics['medium_risks'],
                    'total_low_risks': zap_metrics['low_risks'] + nikto_metrics['low_risks'],
                    'scan_status': 'completed'
                },
                'scan_files': {
                    'output_dir': os.path.abspath(output_dir)
                },
                # Store actual scan results
                'nikto_results': nikto_results,
                'zap_results': zap_results
            }

            # Insert into MongoDB
            result = self.collection.insert_one(document)
            if not result.inserted_id:
                raise Exception("Failed to get inserted document ID")

            print(f"[+] Saved scan results to MongoDB with ID: {result.inserted_id}")
            return str(result.inserted_id)  # Convert ObjectId to string

        except Exception as e:
            print(f"[-] Error saving to MongoDB: {e}")
            return None

    def get_scan_history(self):
        if not self.client:
            return []
        try:
            return list(self.collection.find().sort("timestamp", -1).limit(50))  # Limit to last 50 scans
        except Exception as e:
            print(f"[-] Error retrieving scan history: {e}")
            return []

    def get_report_by_id(self, report_id):
        try:
            from bson.objectid import ObjectId
            
            # Validate report_id format
            if not ObjectId.is_valid(report_id):
                print(f"[-] Invalid report ID format: {report_id}")
                return None
                
            # Find the report
            report = self.collection.find_one({"_id": ObjectId(report_id)})
            
            if report:
                # Process scan results
                if 'nikto_results' in report:
                    self._process_nikto_results(report['nikto_results'])
                if 'zap_results' in report:
                    self._process_zap_results(report['zap_results'])
                    
            return report
            
        except Exception as e:
            print(f"[-] Error retrieving report: {e}")
            return None

    def _process_nikto_results(self, results):
        """Process and clean up Nikto results"""
        if isinstance(results, dict):
            if 'vulnerabilities' in results:
                # Group similar findings
                vuln_map = {}
                for vuln in results['vulnerabilities']:
                    key = f"{vuln.get('id', 'MISC')}:{vuln.get('msg', '')}"
                    if key not in vuln_map:
                        vuln_map[key] = vuln
                    
                results['vulnerabilities'] = list(vuln_map.values())

    def _process_zap_results(self, results):
        """Process and clean up ZAP results"""
        if isinstance(results, dict) and 'alerts' in results:
            # Sort alerts by risk level
            risk_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}
            results['alerts'].sort(key=lambda x: risk_order.get(x.get('risk', 'Low'), 999))
