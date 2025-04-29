from fpdf import FPDF
import json
import os
import time
from datetime import datetime
import traceback
import re
from bson.objectid import ObjectId

def sanitize_text(text):
    """Sanitize and encode text for PDF output"""
    if text is None:
        return ''
    if not isinstance(text, str):
        text = str(text)
    # Remove non-printable characters
    text = ''.join(char for char in text if char.isprintable() or char in ['\n', '\r', '\t'])
    # Convert to UTF-8
    return text.encode('latin-1', errors='replace').decode('latin-1')

class ReportPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'WebAssure Scanner Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', fill=True)
        self.ln(4)

    def chapter_body(self, text):
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 5, text)
        self.ln()

    def cell(self, w=0, h=0, txt='', border=0, ln=0, align='', fill=False, link=''):
        txt = sanitize_text(txt)
        super().cell(w, h, txt, border, ln, align, fill, link)

    def multi_cell(self, w, h, txt='', border=0, align='J', fill=False):
        txt = sanitize_text(txt)
        super().multi_cell(w, h, txt, border, align, fill)

def calculate_metrics(scan_results):
    """Calculate metrics from scan results"""
    metrics = {'zap': {}, 'nikto': {}}
    
    # ZAP metrics
    if 'zap_results' in scan_results:
        alerts = scan_results['zap_results'].get('alerts', [])
        metrics['zap'] = {
            'high_risks': sum(1 for a in alerts if isinstance(a, dict) and a.get('risk') == 'High'),
            'medium_risks': sum(1 for a in alerts if isinstance(a, dict) and a.get('risk') == 'Medium'),
            'low_risks': sum(1 for a in alerts if isinstance(a, dict) and a.get('risk') == 'Low'),
            'info_risks': sum(1 for a in alerts if isinstance(a, dict) and a.get('risk') == 'Informational')
        }
    
    # Nikto metrics
    if 'nikto_results' in scan_results:
        vulns = scan_results['nikto_results'].get('vulnerabilities', [])
        metrics['nikto'] = {
            'total_vulnerabilities': len(vulns),
            'high_risks': sum(1 for v in vulns if isinstance(v, dict) and 
                            any(x in str(v.get('msg', '')).lower() for x in ['sql', 'xss', 'injection', 'remote'])),
            'medium_risks': sum(1 for v in vulns if isinstance(v, dict) and 
                              any(x in str(v.get('msg', '')).lower() for x in ['ssl', 'tls', 'config', 'auth'])),
            'low_risks': sum(1 for v in vulns if isinstance(v, dict) and 
                           not any(x in str(v.get('msg', '')).lower() 
                                 for x in ['sql', 'xss', 'injection', 'remote', 'ssl', 'tls', 'config', 'auth']))
        }
    
    return metrics

def create_pdf_report(scan_results, pdf_type='complete'):
    try:
        print("Creating PDF report with type:", pdf_type)
        print("Scan results type:", type(scan_results))
        
        if not isinstance(scan_results, dict):
            print(f"Error: Invalid scan_results type: {type(scan_results)}")
            return None

        pdf = ReportPDF()
        pdf.add_page()
        
        try:
            # Calculate metrics if not present or invalid
            if 'metrics' not in scan_results or not isinstance(scan_results['metrics'], dict):
                scan_results['metrics'] = calculate_metrics(scan_results)
            
            # Basic information with extra validation
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, "Scan Information", 0, 1)
            pdf.set_font('Arial', '', 11)
            
            # Safely get values with defaults
            target_url = str(scan_results.get('target_url', 'N/A'))
            timestamp = scan_results.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    timestamp = datetime.now()
            
            pdf.cell(0, 8, f"Target URL: {target_url}", 0, 1)
            pdf.cell(0, 8, f"Scan Date: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
            pdf.ln(5)

            # Add appropriate sections based on pdf_type
            if pdf_type in ['complete', 'summary']:
                add_summary_section(pdf, scan_results['metrics'])
            
            if pdf_type == 'complete':
                add_detailed_findings(pdf, scan_results)
            elif pdf_type == 'high-med':
                add_high_medium_findings(pdf, scan_results)
            elif pdf_type == 'high':
                add_high_risk_findings(pdf, scan_results)
            elif pdf_type == 'affected':
                add_affected_points(pdf, scan_results)

            return pdf

        except Exception as e:
            print(f"Error in PDF content generation: {e}")
            traceback.print_exc()
            
            # Create a basic error report
            pdf = ReportPDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, "Error Generating Full Report", 0, 1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 5, f"An error occurred while generating the report: {str(e)}")
            pdf.ln(5)
            pdf.multi_cell(0, 5, "However, we found the following data:")
            pdf.ln(5)
            
            # Try to show whatever data we can
            try:
                if 'target_url' in scan_results:
                    pdf.multi_cell(0, 5, f"Target URL: {scan_results['target_url']}")
                if 'timestamp' in scan_results:
                    pdf.multi_cell(0, 5, f"Scan Date: {scan_results['timestamp']}")
                    
                # Show basic counts even if detailed processing failed
                if 'zap_results' in scan_results:
                    alerts = scan_results['zap_results'].get('alerts', [])
                    pdf.multi_cell(0, 5, f"ZAP Alerts Found: {len(alerts)}")
                    
                if 'nikto_results' in scan_results:
                    vulns = scan_results['nikto_results'].get('vulnerabilities', [])
                    pdf.multi_cell(0, 5, f"Nikto Vulnerabilities Found: {len(vulns)}")
            except:
                pass
                
            return pdf

    except Exception as e:
        print(f"Critical error creating PDF report: {e}")
        traceback.print_exc()
        return None

def generate_pdf_report(scan_results, output_path, pdf_type='complete'):
    try:
        if not isinstance(scan_results, dict):
            print(f"Error: scan_results must be a dictionary, got {type(scan_results)}")
            return False

        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        pdf = create_pdf_report(scan_results, pdf_type)
        if pdf is None:
            return False

        # Make sure we can write to the output path
        try:
            pdf.output(output_path)
            print(f"PDF report generated successfully at: {output_path}")
            return True
        except Exception as e:
            print(f"Error writing PDF to {output_path}: {e}")
            traceback.print_exc()
            return False

    except Exception as e:
        print(f"Error generating PDF: {e}")
        traceback.print_exc()
        return False

def add_summary_section(pdf, metrics):
    pdf.chapter_title("Executive Summary")

    # ZAP Metrics
    zap_metrics = metrics.get('zap', {})
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, "OWASP ZAP Findings:", 0, 1)
    pdf.set_font('Arial', '', 11)
    
    # Add ZAP metrics
    pdf.set_text_color(255, 0, 0)
    pdf.cell(0, 6, f"High Risk Issues: {zap_metrics.get('high_risks', 0)}", 0, 1)
    pdf.set_text_color(255, 165, 0)
    pdf.cell(0, 6, f"Medium Risk Issues: {zap_metrics.get('medium_risks', 0)}", 0, 1)
    pdf.set_text_color(0, 128, 0)
    pdf.cell(0, 6, f"Low Risk Issues: {zap_metrics.get('low_risks', 0)}", 0, 1)
    pdf.set_text_color(0, 0, 255)
    pdf.cell(0, 6, f"Informational Issues: {zap_metrics.get('info_risks', 0)}", 0, 1)
    
    # Reset text color
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # Nikto Metrics
    nikto_metrics = metrics.get('nikto', {})
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 8, "Nikto Findings:", 0, 1)
    pdf.set_font('Arial', '', 11)
    
    pdf.set_text_color(255, 0, 0)
    pdf.cell(0, 6, f"High Risk Issues: {nikto_metrics.get('high_risks', 0)}", 0, 1)
    pdf.set_text_color(255, 165, 0)
    pdf.cell(0, 6, f"Medium Risk Issues: {nikto_metrics.get('medium_risks', 0)}", 0, 1)
    pdf.set_text_color(0, 128, 0)
    pdf.cell(0, 6, f"Low Risk Issues: {nikto_metrics.get('low_risks', 0)}", 0, 1)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 6, f"Total Vulnerabilities: {nikto_metrics.get('total_vulnerabilities', 0)}", 0, 1)

def add_detailed_findings(pdf, scan_results):
    try:
        print("Debug - scan_results structure:", json.dumps(scan_results, default=str, indent=2))
        
        # Get scan results
        zap_data = scan_results.get('zap_results', {})
        nikto_data = scan_results.get('nikto_results', {})

        # Handle ZAP findings
        alerts = zap_data.get('alerts', [])
        if alerts:
            pdf.add_page()
            pdf.chapter_title("OWASP ZAP Findings")
            print(f"Found {len(alerts)} ZAP alerts")

            for alert in alerts:
                pdf.set_font('Arial', 'B', 11)
                risk_level = alert.get('risk', 'Unknown')
                
                # Risk level color coding
                if risk_level.lower() == 'high':
                    pdf.set_text_color(255, 0, 0)
                elif risk_level.lower() == 'medium':
                    pdf.set_text_color(255, 165, 0)
                elif risk_level.lower() == 'low':
                    pdf.set_text_color(0, 128, 0)
                
                pdf.cell(0, 8, f"Finding: {alert.get('name', 'N/A')}", 0, 1)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font('Arial', '', 10)
                
                details = [
                    ('Risk Level', risk_level),
                    ('Confidence', alert.get('confidence', 'N/A')),
                    ('Description', alert.get('description', 'N/A')),
                    ('Solution', alert.get('solution', 'N/A')),
                    ('URL', alert.get('url', '')),
                    ('Parameter', alert.get('param', '')),
                    ('Evidence', alert.get('evidence', '')),
                    ('CWE ID', alert.get('cweid', '')),
                    ('Reference', alert.get('reference', ''))
                ]
                
                for label, value in details:
                    if value:  # Only add if value exists
                        pdf.multi_cell(0, 5, f"{label}: {value}")
                pdf.ln(5)

        # Handle Nikto findings
        vulns = nikto_data.get('vulnerabilities', [])
        if vulns:
            pdf.add_page()
            pdf.chapter_title("Nikto Findings")
            print(f"Found {len(vulns)} Nikto vulnerabilities")

            for vuln in vulns:
                pdf.set_font('Arial', 'B', 11)
                vuln_id = vuln.get('id', 'Unknown')
                
                # Color coding based on vulnerability type
                if any(x in str(vuln.get('msg', '')).lower() for x in ['sql', 'xss', 'injection', 'remote']):
                    pdf.set_text_color(255, 0, 0)
                elif any(x in str(vuln.get('msg', '')).lower() for x in ['ssl', 'tls', 'config']):
                    pdf.set_text_color(255, 165, 0)
                else:
                    pdf.set_text_color(0, 128, 0)
                
                pdf.cell(0, 8, f"Finding ID: {vuln_id}", 0, 1)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font('Arial', '', 10)
                
                if vuln.get('msg'):
                    pdf.multi_cell(0, 5, f"Message: {vuln['msg']}")
                if vuln.get('method'):
                    pdf.multi_cell(0, 5, f"Method: {vuln['method']}")
                if vuln.get('references'):
                    pdf.multi_cell(0, 5, f"References: {vuln['references']}")
                pdf.ln(5)

    except Exception as e:
        print(f"Error in add_detailed_findings: {e}")
        traceback.print_exc()
        pdf.add_page()
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 8, f"Error generating detailed findings: {str(e)}", 0, 1)

def add_high_medium_findings(pdf, scan_results):
    # ZAP high/medium findings
    if 'zap_results' in scan_results:
        alerts = scan_results['zap_results'].get('alerts', [])
        high_med_alerts = [a for a in alerts if a.get('risk') in ['High', 'Medium']]
        
        if high_med_alerts:
            pdf.add_page()
            pdf.chapter_title("High and Medium Risk Findings")
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "OWASP ZAP Findings:", 0, 1)
            
            for alert in high_med_alerts:
                add_finding_to_pdf(pdf, alert, is_zap=True)
    
    # Nikto high/medium findings
    if 'nikto_results' in scan_results:
        vulns = scan_results['nikto_results'].get('vulnerabilities', [])
        high_med_vulns = [v for v in vulns if v.get('id', '').startswith(('INJECT', 'SQL', 'XSS', 'CONFIG', 'SSL', 'AUTH'))]
        
        if high_med_vulns:
            pdf.add_page()
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "Nikto Findings:", 0, 1)
            
            for vuln in high_med_vulns:
                add_finding_to_pdf(pdf, vuln, is_zap=False)

def add_high_risk_findings(pdf, scan_results):
    has_findings = False
    
    # ZAP high findings
    if 'zap_results' in scan_results:
        alerts = scan_results['zap_results'].get('alerts', [])
        high_alerts = [a for a in alerts if a.get('risk') == 'High']
        
        if high_alerts:
            if not has_findings:
                pdf.add_page()
                pdf.chapter_title("High Risk Findings Only")
                has_findings = True
            
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "OWASP ZAP High Risk Findings:", 0, 1)
            
            for alert in high_alerts:
                add_finding_to_pdf(pdf, alert, is_zap=True)
    
    # Nikto high findings
    if 'nikto_results' in scan_results:
        vulns = scan_results['nikto_results'].get('vulnerabilities', [])
        high_vulns = [v for v in vulns if v.get('id', '').startswith(('INJECT', 'SQL', 'XSS'))]
        
        if high_vulns:
            if not has_findings:
                pdf.add_page()
                pdf.chapter_title("High Risk Findings Only")
                has_findings = True
            
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, "Nikto High Risk Findings:", 0, 1)
            
            for vuln in high_vulns:
                add_finding_to_pdf(pdf, vuln, is_zap=False)

def add_affected_points(pdf, scan_results):
    # Collect unique affected URLs/endpoints
    affected_points = set()
    
    # ZAP findings
    if 'zap_results' in scan_results:
        for alert in scan_results['zap_results'].get('alerts', []):
            if 'url' in alert:
                affected_points.add(alert['url'])
    
    # Nikto findings
    if 'nikto_results' in scan_results:
        for vuln in scan_results['nikto_results'].get('vulnerabilities', []):
            if 'url' in vuln:
                affected_points.add(vuln['url'])
    
    # Only add section if there are affected points
    if affected_points:
        pdf.add_page()
        pdf.chapter_title("Affected Points Summary")
        pdf.set_font('Arial', '', 11)
        pdf.cell(0, 8, f"Total Affected Points: {len(affected_points)}", 0, 1)
        pdf.ln(5)
        
        for point in sorted(affected_points):
            pdf.multi_cell(0, 5, f"• {point}")

def add_finding_to_pdf(pdf, finding, is_zap=True):
    try:
        pdf.set_font('Arial', 'B', 10)
        if is_zap:
            risk_level = finding.get('risk', 'Unknown')
            pdf.cell(0, 8, f"Finding: {sanitize_text(finding.get('name', 'N/A'))} ({risk_level})", 0, 1)
            pdf.set_font('Arial', '', 9)
            pdf.multi_cell(0, 5, f"Description: {sanitize_text(finding.get('description', 'N/A'))}")
            pdf.multi_cell(0, 5, f"Solution: {sanitize_text(finding.get('solution', 'N/A'))}")
            if finding.get('url'):
                pdf.multi_cell(0, 5, f"URL: {sanitize_text(finding['url'])}")
            if finding.get('references'):
                pdf.multi_cell(0, 5, f"References: {sanitize_text(finding['references'])}")
        else:
            pdf.cell(0, 8, f"ID: {sanitize_text(finding.get('id', 'N/A'))}", 0, 1)
            pdf.set_font('Arial', '', 9)
            pdf.multi_cell(0, 5, f"Finding: {sanitize_text(finding.get('msg', 'N/A'))}")
            if finding.get('references'):
                pdf.multi_cell(0, 5, f"References: {sanitize_text(finding['references'])}")
        pdf.ln(5)
    except Exception as e:
        print(f"Error adding finding to PDF: {e}")
        # Continue with next finding
